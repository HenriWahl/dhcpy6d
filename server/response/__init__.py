# DHCPy6d DHCPv6 Daemon
#
# Copyright (C) 2009-2019 Henri Wahl <h.wahl@ifw-dresden.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

import binascii
from copy import deepcopy
import socket
import socketserver
import sys
import time
import traceback

from .. import collect_macs
from ..client import Client
from ..config import cfg
from ..constants import MESSAGE_TYPES
from ..dns import (dns_delete,
                   dns_update)
from ..globals import (collected_macs,
                       DUMMY_MAC,
                       IA_OPTIONS,
                       requests,
                       requests_blacklist,
                       timer,
                       transactions)
from ..helpers import (build_option,
                       colonify_ip6,
                       convert_dns_to_binary,
                       decompress_ip6,
                       LOCALHOST,
                       LOCALHOST_INTERFACES)
from ..log import log
from ..route import modify_route
from ..storage import (config_store,
                       volatile_store)
from ..transaction import Transaction


class Request:
    """
        to be stored in requests dictionary to log client requests to be able to find brute force clients
    """
    def __init__(self, client):
        self.client = client
        self.count = 1
        self.timestamp = timer


class Handler(socketserver.DatagramRequestHandler):
    """
        manage all incoming datagrams
    """

    def handle(self):
        """
        request handling happens here
        """
        # empty dummy response
        self.response = ''

        # raw address+interface, used for requests monitoring
        client_address = deepcopy(self.client_address[0])
        try:
            interface = socket.if_indextoname(self.client_address[3])
        except OSError:
            # strangely the interface index is 0 if sent to localhost -
            # even if 'lo' has the index 1
            interface = ''

        # avoid processing requests of unknown clients which cannot be found in the neighbor cache table
        # only makes sense if classes are not ignored and thus the neighbor cache is used
        if not cfg.IGNORE_MAC and cfg.IGNORE_UNKNOWN_CLIENTS:
            if client_address in requests_blacklist:
                return False

        # default is no control request
        self.is_control_message = False

        # check if we are limiting requests
        if cfg.REQUEST_LIMIT:
            if cfg.REQUEST_LIMIT_IDENTIFICATION == 'llip':
                # avoid further processing if client is known to be bad
                if client_address in requests_blacklist:
                    return False
                # add client to requests tracker if not known, otherwise raise counter
                if client_address not in requests:
                    requests[client_address] = Request(client_address)
                else:
                    requests[client_address].count += 1
            # otherwise a MAC address
            else:
                # llip = decompress_ip6(client_address.split('%')[0])
                llip = decompress_ip6(client_address)
                if llip in collected_macs:
                    mac = deepcopy(collected_macs[llip].mac)
                    if mac in requests_blacklist:
                        return False
                    # add client to requests tracker if not known, otherwise raise counter
                    if mac not in requests:
                        requests[mac] = Request(mac)
                    else:
                        requests[mac].count += 1
                del llip
        try:
            # convert raw message into ascii-bytes
            raw_bytes = binascii.hexlify(self.request[0]).decode()

            # local connection is a control message
            # for BSD there might be different localhost addresses
            if client_address == LOCALHOST and interface in LOCALHOST_INTERFACES:
                self.is_control_message = True

            # do nothing if interface is not configured
            if not interface in cfg.INTERFACE and not self.is_control_message:
                return False

            # bad or too short message is thrown away
            if not len(raw_bytes) > 8:
                pass
            elif self.is_control_message:
                self.control_message(raw_bytes)
            else:
                message_type = int(raw_bytes[0:2], 16)
                transaction_id = raw_bytes[2:8]
                raw_bytes_options = raw_bytes[8:]
                options = {}
                while len(raw_bytes_options) > 0:
                    # option type and length are 2 bytes each
                    option = int(raw_bytes_options[0:4], 16)
                    length = int(raw_bytes_options[4:8], 16)
                    # *2 because 2 bytes make 1 char
                    value = raw_bytes_options[8:8 + length*2]
                    # Microsoft behaves a little bit different than the other
                    # clients - in RENEW and REBIND request multiple addresses of an
                    # IAID are not requested all in one option type 3 but
                    # come in several options of type 3 what leads to some confusion
                    if not option in IA_OPTIONS:
                        options[option] = value
                    else:
                        if option in options:
                            # if options list already exists append value
                            options[option].append(value)
                        else:
                            # otherwise create list and put value in
                            options[option] = [value]

                    # cut off bytes worked on
                    raw_bytes_options = raw_bytes_options[8 + length*2:]

                # only valid messages will be processed
                if message_type in MESSAGE_TYPES:
                    # 2. create Transaction object if not yet done
                    if not transaction_id in transactions:
                        client_llip = decompress_ip6(client_address)
                        transactions[transaction_id] = Transaction(transaction_id, client_llip, interface, message_type, options)
                        # add client MAC address to transaction object
                        if transactions[transaction_id].ClientLLIP in collected_macs:
                            if not cfg.IGNORE_MAC:
                                transactions[transaction_id].MAC = collected_macs[transactions[transaction_id].ClientLLIP].mac
                    else:
                        transactions[transaction_id].Timestamp = timer
                        transactions[transaction_id].LastMessageReceivedType = message_type

                    # log incoming messages
                    log.info('%s | TransactionID: %s%s' % (MESSAGE_TYPES[message_type], transaction_id, transactions[transaction_id]._get_options_string()))

                    # 3. answer requests
                    # check if client sent a valid DUID (alphanumeric)
                    if transactions[transaction_id].DUID.isalnum():
                        # if request was not addressed to multicast do nothing but logging
                        if transactions[transaction_id].Interface == '':
                            log.info('TransactionID: %s | %s' % (transaction_id, 'Multicast necessary but message came from %s' % (colonify_ip6(transactions[transaction_id].ClientLLIP))))
                            # reset transaction counter
                            transactions[transaction_id].Counter = 0
                        else:
                            # client will get answer if its LLIP & MAC is known
                            if not transactions[transaction_id].ClientLLIP in collected_macs:
                                if not cfg.IGNORE_MAC:
                                    # complete MAC collection - will make most sence on Linux and its native neighborcache access
                                    collect_macs(timer)

                                    # when still no trace of the client in neighbor cache then send silly signal back
                                    if not transactions[transaction_id].ClientLLIP in collected_macs:
                                        # if not known send status code option failure to get
                                        # LLIP/MAC mapping from neighbor cache
                                        # status code 'Success' sounds silly but works best
                                        self.build_response(7, transaction_id, [13], status=0)
                                        # complete MAC collection
                                        collect_macs(timer)
                                        # if client cannot be found in collected MACs
                                        if not transactions[transaction_id].ClientLLIP in collected_macs:
                                            if cfg.IGNORE_UNKNOWN_CLIENTS and client_address in requests:
                                                if requests[client_address].count > 1:
                                                    requests_blacklist[client_address] = Request(client_address)
                                                    log.info("Blacklisting unknown client {0}".format(client_address))
                                                    return False

                                    # try to add client MAC address to transaction object
                                    try:
                                        transactions[transaction_id].MAC = collected_macs[transactions[transaction_id].ClientLLIP].mac
                                    except:
                                        # MAC not yet found :-(
                                        if cfg.LOG_MAC_LLIP:
                                            log.info('TransactionID: %s | %s' % (transaction_id, 'MAC address for LinkLocalIP %s unknown' % (colonify_ip6(transactions[transaction_id].ClientLLIP))))

                            # if finally there is some info about the client or MACs play no role try to answer the request
                            if transactions[transaction_id].ClientLLIP in collected_macs or cfg.IGNORE_MAC:
                                if not cfg.IGNORE_MAC:
                                    if transactions[transaction_id].MAC == DUMMY_MAC:
                                        transactions[transaction_id].MAC = collected_macs[transactions[transaction_id].ClientLLIP].mac

                                # ADVERTISE
                                # if last request was a SOLICIT send an ADVERTISE (type 2) back
                                if transactions[transaction_id].LastMessageReceivedType == 1 \
                                   and transactions[transaction_id].RapidCommit == False:
                                    # preference option (7) is for free
                                    self.build_response(2, transaction_id, transactions[transaction_id].IA_Options + \
                                                        [7] + transactions[transaction_id].OptionsRequest)

                                    # store leases for addresses and lock advertised address
                                    #volatilestore.store(transaction_id, timer)
                                    volatile_store.store(deepcopy(transactions[transaction_id]), timer)

                                # REQUEST
                                # if last request was a REQUEST (type 3) send a REPLY (type 7) back
                                elif transactions[transaction_id].LastMessageReceivedType == 3 or \
                                     (transactions[transaction_id].LastMessageReceivedType == 1 and \
                                      transactions[transaction_id].RapidCommit == True):
                                    # preference option (7) is for free
                                    # if RapidCommit was set give it back
                                    if not transactions[transaction_id].RapidCommit:
                                        self.build_response(7, transaction_id, transactions[transaction_id].IA_Options + \
                                                            [7] + transactions[transaction_id].OptionsRequest)
                                    else:
                                        self.build_response(7, transaction_id, transactions[transaction_id].IA_Options + \
                                                            [7] + [14] + transactions[transaction_id].OptionsRequest)
                                    # store leases for addresses
                                    #volatilestore.store(transaction_id, timer)
                                    volatile_store.store(deepcopy(transactions[transaction_id]), timer)

                                    # run external script for setting a route to the delegated prefix
                                    if 25 in transactions[transaction_id].IA_Options:
                                        modify_route(transaction_id, 'up')

                                    if cfg.DNS_UPDATE:
                                        dns_update(transaction_id)

                                # CONFIRM
                                # if last request was a CONFIRM (4) send a REPLY (type 7) back
                                # Due to problems with different clients they will get a not-available-reply
                                # but the next ADVERTISE will offer them the last known and still active
                                # lease. This makes sense in case of fixed MAC-based, addresses, ranges and
                                # ID-based addresses, Random addresses will be recalculated
                                elif transactions[transaction_id].LastMessageReceivedType == 4:
                                    # the RFC 3315 is a little bit confusing regarding CONFIRM
                                    # messages so it won't hurt to simply let the client
                                    # solicit addresses again via answering 'NotOnLink'
                                    # thus client is forced in every case to solicit a new address which
                                    # might as well be the old one or a new if prefix has changed
                                    self.build_response(7, transaction_id, [13], status=4)

                                # RENEW
                                # if last request was a RENEW (type 5) send a REPLY (type 7) back
                                elif transactions[transaction_id].LastMessageReceivedType == 5:
                                    self.build_response(7, transaction_id, transactions[transaction_id].IA_Options + [7] + \
                                                        transactions[transaction_id].OptionsRequest)
                                    # store leases for addresses
                                    #volatilestore.store(transaction_id, timer)
                                    volatile_store.store(deepcopy(transactions[transaction_id]), timer)
                                    if cfg.DNS_UPDATE:
                                        dns_update(transaction_id)

                                # REBIND
                                # if last request was a REBIND (type 6) send a REPLY (type 7) back
                                elif transactions[transaction_id].LastMessageReceivedType == 6:
                                    self.build_response(7, transaction_id, transactions[transaction_id].IA_Options + [7] + \
                                                        transactions[transaction_id].OptionsRequest)
                                    # store leases for addresses
                                    #volatilestore.store(transaction_id, timer)
                                    volatile_store.store(deepcopy(transactions[transaction_id]), timer)

                                # RELEASE
                                # if last request was a RELEASE (type 8) send a REPLY (type 7) back
                                elif transactions[transaction_id].LastMessageReceivedType == 8:
                                    #  build client to be able to delete it from DNS
                                    if transactions[transaction_id].Client == None:
                                        # transactions[transaction_id].Client = build_client(transaction_id)
                                        transactions[transaction_id].Client = Client(transaction_id)
                                    if cfg.DNS_UPDATE:
                                        for a in transactions[transaction_id].Addresses:
                                            dns_delete(transaction_id, address=a, action='release')
                                    for a in transactions[transaction_id].Addresses:
                                        # free lease
                                        volatile_store.release_lease(a, timer)
                                    for p in transactions[transaction_id].Prefixes:
                                        # free prefix - without length
                                        volatile_store.release_prefix(p.split('/')[0], timer)
                                        # delete route to formerly requesting client
                                        modify_route(transaction_id, 'down')
                                    # send status code option (type 13) with success (type 0)
                                    self.build_response(7, transaction_id, [13], status=0)

                                # DECLINE
                                # if last request was a DECLINE (type 9) send a REPLY (type 7) back
                                elif transactions[transaction_id].LastMessageReceivedType == 9:
                                    # maybe has to be refined - now only a status code 'NoBinding' is answered
                                    self.build_response(7, transaction_id, [13], status=3)

                                # INFORMATION-REQUEST
                                # if last request was an INFORMATION-REQUEST (type 11) send a REPLY (type 7) back
                                elif transactions[transaction_id].LastMessageReceivedType == 11:
                                    self.build_response(7, transaction_id, transactions[transaction_id].OptionsRequest)

                                # general error - statuscode 1 'Failure'
                                else:
                                    # send Status Code Option (type 13) with status code 'UnspecFail'
                                    self.build_response(7, transaction_id, [13], status=1)

                    # count requests of transaction
                    # if there will be too much something went wrong
                    # may be evaluated to reset the whole transaction
                    transactions[transaction_id].Counter += 1

        except Exception as err:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            log.error('handle(): %s | Caused by: %s | Transaction: %s' % (str(err), client_address, transaction_id))
            return None

    def build_response(self, response_type, transaction_id, options_request, status=0):
        """
            creates answer and puts it into self.response
            arguments:
                response_type - mostly 2 or 7
                transaction_id
                option_request
                status - mostly 0 (OK)
            response will be sent by self.finish()
        """
        try:
            # Header
            # response type + transaction id
            response_ascii = '%02x' % (response_type)
            #response_ascii += transaction_id.encode()
            response_ascii += transaction_id

            # these options are always useful
            # Option 1 client identifier
            response_ascii += build_option(1, transactions[transaction_id].DUID)
            # Option 2 server identifier
            response_ascii += build_option(2, cfg.SERVERDUID)

            # list of options in answer to be logged
            options_answer = []

            # IA_NA non-temporary addresses
            # Option 3 + 5 Identity Association for Non-temporary Address
            if 3 in options_request:
                # check if MAC of LLIP is really known
                if transactions[transaction_id].ClientLLIP in collected_macs or cfg.IGNORE_MAC:
                    # collect client information
                    if transactions[transaction_id].Client == None:
                        # transactions[transaction_id].Client = build_client(transaction_id)
                        transactions[transaction_id].Client = Client(transaction_id)

                    if 'addresses' in cfg.CLASSES[transactions[transaction_id].Client.Class].ADVERTISE and \
                                    (3 or 4) in transactions[transaction_id].IA_Options:
                        # check if only a short NoAddrAvail answer or none at all is to be returned
                        if not transactions[transaction_id].Answer == 'normal':
                            if transactions[transaction_id].Answer == 'noaddress':
                                # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                                response_ascii += build_option(13, '%04x' % (2))
                                # clean client addresses which not be deployed anyway
                                transactions[transaction_id].Client.Addresses[:] = []
                                # options in answer to be logged
                                options_answer.append(13)
                            else:
                                # clean response as there is nothing to respond in case of answer = none
                                self.response = ''
                                return None
                        else:
                            # if client could not be built because of database problems send
                            # status message back
                            if transactions[transaction_id].Client:
                                # embed option 5 into option 3 - several if necessary
                                ia_addresses = ''
                                try:
                                    for address in transactions[transaction_id].Client.Addresses:
                                        if address.IA_TYPE == 'na':
                                            ipv6_address = binascii.b2a_hex(socket.inet_pton(socket.AF_INET6,
                                                                                             colonify_ip6(address.ADDRESS))).decode()
                                            # if a transaction consists of too many requests from client -
                                            # - might be caused by going wild Windows clients -
                                            # reset all addresses with lifetime 0
                                            # lets start with maximal transaction count of 10
                                            if transactions[transaction_id].Counter < 10:
                                                preferred_lifetime = '%08x' % (int(address.PREFERRED_LIFETIME))
                                                valid_lifetime = '%08x' % (int(address.VALID_LIFETIME))
                                            else:
                                                preferred_lifetime = '%08x' % (0)
                                                valid_lifetime = '%08x' % (0)
                                            ia_addresses += build_option(5, ipv6_address + preferred_lifetime + valid_lifetime)

                                    if not ia_addresses == '':
                                        #
                                        # todo: default clients sometimes seem to have class ''
                                        #
                                        if transactions[transaction_id].Client.Class != '':
                                            t1 = '%08x' % (int(cfg.CLASSES[transactions[transaction_id].Client.Class].T1))
                                            t2 = '%08x' % (int(cfg.CLASSES[transactions[transaction_id].Client.Class].T2))
                                        else:
                                            t1 = '%08x' % (int(cfg.T1))
                                            t2 = '%08x' % (int(cfg.T2))

                                        response_ascii += build_option(3, transactions[transaction_id].IAID + t1 + t2 + ia_addresses)
                                    # options in answer to be logged
                                    options_answer.append(3)
                                except:
                                    # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                                    response_ascii += build_option(13, '%04x' % (2))
                                    # options in answer to be logged
                                    options_answer.append(13)
                            else:
                                # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                                response_ascii += build_option(13, '%04x' % (2))
                                # options in answer to be logged
                                options_answer.append(13)

            # IA_TA temporary addresses
            if 4 in options_request:
                # check if MAC of LLIP is really known
                if transactions[transaction_id].ClientLLIP in collected_macs or cfg.IGNORE_MAC:
                    # collect client information
                    if transactions[transaction_id].Client == None:
                        # transactions[transaction_id].Client = build_client(transaction_id)
                        transactions[transaction_id].Client = Client(transaction_id)

                    if 'addresses' in cfg.CLASSES[transactions[transaction_id].Client.Class].ADVERTISE and \
                        (3 or 4) in transactions[transaction_id].IA_Options:
                        # check if only a short NoAddrAvail answer or none at all ist t be returned
                        if not transactions[transaction_id].Answer == 'normal':
                            if transactions[transaction_id].Answer == 'noaddress':
                                # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                                response_ascii += build_option(13, '%04x' % (2))
                                # clean client addresses which not be deployed anyway
                                transactions[transaction_id].Client.Addresses[:] = []
                                # options in answer to be logged
                                options_answer.append(13)
                            else:
                                # clean response as there is nothing to respond in case of answer = none
                                self.response = ''
                                return None
                        else:
                            # if client could not be built because of database problems send
                            # status message back
                            if transactions[transaction_id].Client:
                                # embed option 5 into option 4 - several if necessary
                                ia_addresses = ''
                                try:
                                    for address in transactions[transaction_id].Client.Addresses:
                                        if address.IA_TYPE == 'ta':
                                            ipv6_address = binascii.b2a_hex(socket.inet_pton(socket.AF_INET6,
                                                                                             colonify_ip6(address.ADDRESS))).decode()
                                            # if a transaction consists of too many requests from client -
                                            # - might be caused by going wild Windows clients -
                                            # reset all addresses with lifetime 0
                                            # lets start with maximal transaction count of 10
                                            if transactions[transaction_id].Counter < 10:
                                                preferred_lifetime = '%08x' % (int(address.PREFERRED_LIFETIME))
                                                valid_lifetime = '%08x' % (int(address.VALID_LIFETIME))
                                            else:
                                                preferred_lifetime = '%08x' % (0)
                                                valid_lifetime = '%08x' % (0)
                                            ia_addresses += build_option(5, ipv6_address + preferred_lifetime + valid_lifetime)
                                    if not ia_addresses == '':
                                        response_ascii += build_option(4, transactions[transaction_id].IAID + ia_addresses)
                                    # options in answer to be logged
                                    options_answer.append(4)
                                except:
                                    # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                                    response_ascii += build_option(13, '%04x' % (2))
                                    # options in answer to be logged
                                    options_answer.append(13)
                            else:
                                # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                                response_ascii += build_option(13, '%04x' % (2))
                                # options in answer to be logged
                                options_answer.append(13)

            # Option 7 Server Preference
            if 7 in options_request:
                response_ascii += build_option(7, '%02x' % (int(cfg.SERVER_PREFERENCE)))
                # options in answer to be logged
                options_answer.append(7)

            # Option 11 Authentication Option
            # seems to be pretty unused at the moment - to be done
            if 11 in options_request:
                # '3' for Reconfigure Key Authentication Protocol
                protocol = '%02x' % (3)
                # '1' for algorithm
                algorithm = '%02x' % (1)
                # assuming '0' as valid Replay Detection method
                rdm = '%02x' % (0)
                # Replay Detection - current time for example
                replay_detection = '%016x' % (int(time.time()))
                # Authentication Information Type
                # first 1, later with HMAC-MD5  2
                ai_type = '%02x' % (1)
                authentication_information = cfg.AUTHENTICATION_INFORMATION
                # stuffed together
                response_ascii += build_option(11, protocol + algorithm + rdm + replay_detection + ai_type + authentication_information)
                # options in answer to be logged
                options_answer.append(11)

            # Option 12 Server Unicast Option
            if 12 in options_request:
                response_ascii += build_option(12, binascii.b2a_hex(socket.inet_pton(socket.AF_INET6, cfg.ADDRESS)).decode())
                # options in answer to be logged
                options_answer.append(12)

            # Option 13 Status Code Option - statuscode is taken from dictionary
            if 13 in options_request:
                response_ascii += build_option(13, '%04x' % (status))
                # options in answer to be logged
                options_answer.append(13)

            # Option 14 Rapid Commit Option - necessary for REPLY to SOLICIT message with Rapid Commit
            if 14 in options_request:
                response_ascii += build_option(14, '')
                # options in answer to be logged
                options_answer.append(14)

            # Option 23 DNS recursive name server
            if 23 in options_request:
                # should not be necessary to check if Transactions[transaction_id].Client exists but there are
                # crazy clients out in the wild which might become silent this way
                if transactions[transaction_id].Client:
                    if len(cfg.CLASSES[transactions[transaction_id].Client.Class].NAMESERVER) > 0:
                        nameserver = ''
                        for ns in cfg.CLASSES[transactions[transaction_id].Client.Class].NAMESERVER:
                            nameserver += socket.inet_pton(socket.AF_INET6, ns)
                        response_ascii += build_option(23, binascii.b2a_hex(nameserver).decode())
                        # options in answer to be logged
                        options_answer.append(23)

                elif len(cfg.NAMESERVER) > 0:
                    # in case several nameservers are given convert them all and add them
                    nameserver = ''
                    for ns in cfg.NAMESERVER:
                        nameserver += socket.inet_pton(socket.AF_INET6, ns)
                    response_ascii += build_option(23, binascii.b2a_hex(nameserver).decode())
                    # options in answer to be logged
                    options_answer.append(23)

            # Option 24 Domain Search List
            if 24 in options_request:
                converted_domain_search_list = ''
                for d in cfg.DOMAIN_SEARCH_LIST:
                    converted_domain_search_list += convert_dns_to_binary(d)
                response_ascii += build_option(24, converted_domain_search_list)
                # options in answer to be logged
                options_answer.append(24)

            # Option 25 Prefix Delegation
            if 25 in options_request:
                # check if MAC of LLIP is really known
                if transactions[transaction_id].ClientLLIP in collected_macs or cfg.IGNORE_MAC:
                    # collect client information
                    if transactions[transaction_id].Client == None:
                        # transactions[transaction_id].Client = build_client(transaction_id)
                        transactions[transaction_id].Client = Client(transaction_id)

                    # Only if prefixes are provided
                    if 'prefixes' in cfg.CLASSES[transactions[transaction_id].Client.Class].ADVERTISE:
                        # check if only a short NoPrefixAvail answer or none at all is to be returned
                        if not transactions[transaction_id].Answer == 'normal':
                            if transactions[transaction_id].Answer == 'noprefix':
                                # Option 13 Status Code Option - statuscode is 6: 'No Prefix available'
                                response_ascii += build_option(13, '%04x' % (6))
                                # clean client prefixes which not be deployed anyway
                                transactions[transaction_id].Client.Prefixes[:] = []
                                # options in answer to be logged
                                options_answer.append(13)
                            else:
                                # clean response as there is nothing to respond in case of answer = none
                                self.response = ''
                                return None
                        else:
                            # if client could not be built because of database problems send
                            # status message back
                            if transactions[transaction_id].Client:
                                # embed option 26 into option 25 - several if necessary
                                ia_prefixes = ''
                                try:
                                    for prefix in transactions[transaction_id].Client.Prefixes:
                                        ipv6_prefix = binascii.b2a_hex(socket.inet_pton(socket.AF_INET6,
                                                                                        colonify_ip6(prefix.PREFIX))).decode()
                                        if prefix.VALID:
                                            preferred_lifetime = '%08x' % (int(prefix.PREFERRED_LIFETIME))
                                            valid_lifetime = '%08x' % (int(prefix.VALID_LIFETIME))
                                        else:
                                            preferred_lifetime = '%08x' % (0)
                                            valid_lifetime = '%08x' % (0)
                                        length = '%02x' % (int(prefix.LENGTH))
                                        ia_prefixes += build_option(26, preferred_lifetime + valid_lifetime + length + ipv6_prefix)

                                    if transactions[transaction_id].Client.Class != '':
                                        t1 = '%08x' % (int(cfg.CLASSES[transactions[transaction_id].Client.Class].T1))
                                        t2 = '%08x' % (int(cfg.CLASSES[transactions[transaction_id].Client.Class].T2))
                                    else:
                                        t1 = '%08x' % (int(cfg.T1))
                                        t2 = '%08x' % (int(cfg.T2))

                                    # even if there anre no prefixes server has to deliver an empty PD
                                    response_ascii += build_option(25, transactions[transaction_id].IAID + t1 + t2 + ia_prefixes)
                                    # if no prefixes available a NoPrefixAvail status code has to be sent
                                    if ia_prefixes == '':
                                        # REBIND not possible
                                        if transactions[transaction_id].LastMessageReceivedType == 6:
                                            # Option 13 Status Code Option - statuscode is 3: 'NoBinding'
                                            response_ascii += build_option(13, '%04x' % (3))
                                        else:
                                            # Option 13 Status Code Option - statuscode is 6: 'No Prefix available'
                                            response_ascii += build_option(13, '%04x' % (6))
                                    # options in answer to be logged
                                    options_answer.append(25)

                                except Exception as err:
                                    print(err)
                                    # Option 13 Status Code Option - statuscode is 6: 'No Prefix available'
                                    response_ascii += build_option(13, '%04x' % (6))
                                    # options in answer to be logged
                                    options_answer.append(25)
                            else:
                                # Option 13 Status Code Option - statuscode is 6: 'No Prefix available'
                                response_ascii += build_option(13, '%04x' % (6))
                                # options in answer to be logged
                                options_answer.append(25)

            # Option 31 OPTION_SNTP_SERVERS
            if 31 in options_request and cfg.SNTP_SERVERS != '':
                sntp_servers = ''
                for s in cfg.SNTP_SERVERS:
                    sntp_server = binascii.b2a_hex(socket.inet_pton(socket.AF_INET6, s)).decode()
                    sntp_servers += sntp_server
                response_ascii += build_option(31, sntp_servers)

            # Option 32 Information Refresh Time
            if 32 in options_request:
                response_ascii += build_option(32, '%08x' % int(cfg.INFORMATION_REFRESH_TIME))
                # options in answer to be logged
                options_answer.append(32)

            # Option 39 FQDN
            # http://tools.ietf.org/html/rfc4704#page-5
            # regarding RFC 4704 5. there are 3 kinds of client behaviour for N O S:
            # - client wants to update DNS itself -> sends 0 0 0
            # - client wants server to update DNS -> sends 0 0 1
            # - client wants no server DNS update -> sends 1 0 0
            if 39 in options_request and transactions[transaction_id].Client:
                # flags for answer
                N, O, S = 0, 0, 0
                # use hostname supplied by client
                if cfg.DNS_USE_CLIENT_HOSTNAME:
                    hostname = transactions[transaction_id].Hostname
                # use hostname from config
                else:
                    hostname = transactions[transaction_id].Client.Hostname
                if not hostname == '':
                    if cfg.DNS_UPDATE == 1:
                        # DNS update done by server - don't care what client wants
                        if cfg.DNS_IGNORE_CLIENT:
                            S = 1
                            O = 1
                        else:
                            # honor the client's request for the server to initiate DNS updates
                            if transactions[transaction_id].DNS_S == 1:
                                S = 1
                            # honor the client's request for no server-initiated DNS update
                            elif  transactions[transaction_id].DNS_N == 1:
                                N = 1
                    else:
                        # no DNS update at all, not for server and not for client
                        if transactions[transaction_id].DNS_N == 1 or\
                           transactions[transaction_id].DNS_S == 1:
                            O = 1

                    # sum of flags
                    nos_flags = N*4 + O*2 + S*1

                    response_ascii += build_option(39, '%02x' % (nos_flags) + convert_dns_to_binary(hostname + '.' + cfg.DOMAIN))
                else:
                    # if no hostname given put something in and force client override
                    response_ascii += build_option(39, '%02x' % (3) + convert_dns_to_binary('invalid-hostname'))
                # options in answer to be logged
                options_answer.append(39)

            # Option 56 NTP server
            # https://tools.ietf.org/html/rfc5908
            if 56 in options_request:
                ntp_server_options = ''
                if len(cfg.NTP_SERVER) > 0:
                    for ntp_server_type in list(cfg.NTP_SERVER_dict.keys()):
                        # ntp_server_suboption
                        for ntp_server in cfg.NTP_SERVER_dict[ntp_server_type]:
                            ntp_server_suboption = ''
                            if ntp_server_type == 'SRV':
                                ntp_server_suboption = build_option(1, binascii.b2a_hex(socket.inet_pton(socket.AF_INET6, ntp_server)).decode())
                            elif ntp_server_type == 'MC':
                                ntp_server_suboption = build_option(2, binascii.b2a_hex(socket.inet_pton(socket.AF_INET6, ntp_server)).decode())
                            elif ntp_server_type == 'FQDN':
                                ntp_server_suboption = build_option(3, convert_dns_to_binary(ntp_server))
                            ntp_server_options += ntp_server_suboption
                    response_ascii += build_option(56, ntp_server_options)
                    # options in answer to be logged
                    options_answer.append(56)

            # Option 59 Network Boot
            # https://tools.ietf.org/html/rfc5970
            if 59 in options_request:
                # build client if not done yet
                if transactions[transaction_id].Client == None:
                    # transactions[transaction_id].Client = build_client(transaction_id)
                    transactions[transaction_id].Client = Client(transaction_id)

                bootfiles = transactions[transaction_id].Client.Bootfiles
                if len(bootfiles) > 0:
                    # TODO add preference logic
                    bootfile_url = bootfiles[0].BOOTFILE_URL
                    transactions[transaction_id].Client.ChosenBootFile = bootfile_url
                    bootfile_options = binascii.b2a_hex(bootfile_url).decode()
                    response_ascii += build_option(59, bootfile_options)
                    # options in answer to be logged
                    options_answer.append(59)

            # if databases are not connected send error to client
            if not (config_store.connected == volatile_store.connected == True):
                # mark database errors - every database may add its error
                dberror = []
                if not config_store.connected:
                    dberror.append('config')
                    config_store.DBConnect()
                if not volatile_store.connected:
                    dberror.append('volatile')
                    volatile_store.DBConnect()

                # create error response - headers have to be recreated because
                # problems may have arisen while processing and these information
                # is not valid anymore
                # response type + transaction id
                response_ascii = '%02x' % (7)
                response_ascii += transaction_id

                # always of interest
                # option 1 client identifier
                response_ascii += build_option(1, transactions[transaction_id].DUID)
                # option 2 server identifier
                response_ascii += build_option(2, cfg.SERVERDUID)

                # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                response_ascii += build_option(13, '%04x' % (2))

                log.error('%s| TransactionID: %s | DatabaseError: %s' % (MESSAGE_TYPES[response_type], transaction_id, ' '.join(dberror)))

            else:
                # log response
                if not transactions[transaction_id].Client is None:
                    if len(transactions[transaction_id].Client.Addresses) == 0 and\
                       len(transactions[transaction_id].Client.Prefixes) == 0 and\
                       transactions[transaction_id].Answer == 'normal' and\
                       transactions[transaction_id].LastMessageReceivedType in [1, 3, 5, 6]:
                        # create error response - headers have to be recreated because
                        # problems may have arisen while processing and these information
                        # is not valid anymore
                        # response type + transaction id
                        response_ascii = '%02x' % (7)
                        response_ascii += transaction_id

                        # always of interest
                        # option 1 client identifier
                        response_ascii += build_option(1, transactions[transaction_id].DUID)
                        # option 2 server identifier
                        response_ascii += build_option(2, cfg.SERVERDUID)

                        # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                        response_ascii += build_option(13, '%04x' % (2))
                        # options in answer to be logged
                        options_answer.append(13)

                        # log warning message about unavailable addresses
                        log.warning('REPLY | No addresses or prefixes available | TransactionID: %s | ClientLLIP: %s' % \
                                    (transaction_id, colonify_ip6(transactions[transaction_id].ClientLLIP)))

                    elif 3 in options_request or 4 in options_request or 13 in options_request or 25 in options_request:
                        # options_answer.sort()
                        options_answer = sorted(options_answer)
                        log.info('%s | TransactionID: %s | Options: %s%s' % (MESSAGE_TYPES[response_type], transaction_id, options_answer, transactions[transaction_id].Client._get_options_string()))
                    else:
                        print(options_request)
                        log.info('what else should I do?')
                else:
                    # options_answer.sort()
                    options_answer = sorted(options_answer)
                    log.info('%s | TransactionID: %s | Options: %s' % (MESSAGE_TYPES[response_type], transaction_id, options_answer))

            # response
            self.response = binascii.a2b_hex(response_ascii)

        except Exception as err:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            log.error('Response(): ' + str(err))
            print(transaction_id)
            print(transactions[transaction_id].Client.__dict__)

            # clear any response
            self.response = ''

            return None

    def finish(self):
        """
        send response from self.response
        """
        # send only if there is anything to send
        if cfg.REALLY_DO_IT:
            if len(self.response) > 0:
                self.socket.sendto(self.response, self.client_address)
        else:
            log.error("Nothing sent - please set 'really_do_it = yes' in config file or as command line option.")

    def control_message(self, raw_bytes):
        """
        execute commands sent in by control message
        """
        control_message = binascii.unhexlify(raw_bytes)
        control_message_fragments = control_message.decode().split(' ')
        # clean message
        control_message_clean = list()
        for count in range(len(control_message_fragments)):
            if control_message_fragments[count] != '':
                control_message_clean.append(control_message_fragments[count])
        command = control_message_clean[0]
        arguments = control_message_clean[1:]

        # change dynamic prefix
        if command == 'prefix' and len(arguments) == 1:
            cfg.PREFIX = arguments[0]
            volatile_store.store_dynamic_prefix(cfg.PREFIX)
        log.info('Control message "%s" received' % ' '.join(control_message_clean))
