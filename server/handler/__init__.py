# DHCPy6d DHCPv6 Daemon
#
# Copyright (C) 2009-2020 Henri Wahl <h.wahl@ifw-dresden.de>
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
import traceback

from .. import collect_macs
from ..client import Client
from ..config import cfg
from ..constants import (MESSAGE_TYPE_ADVERTISE,
                         MESSAGE_TYPE_REPLY,
                         MESSAGE_TYPES)
from ..domain import (dns_delete,
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
from ..options import options
from ..route import modify_route
from ..storage import (config_store,
                       volatile_store)
from ..transaction import Transaction

from . import (option_12,
               option_13,
               option_14,
               option_23,
               option_24,
               option_25)


class Request:
    """
        to be stored in requests dictionary to log client requests to be able to find brute force clients
    """
    def __init__(self, client):
        self.client = client
        self.count = 1
        self.timestamp = timer


class RequestHandler(socketserver.DatagramRequestHandler):
    """
        manage all incoming datagrams, builds clients from config and previous leases
    """
    # empty dummy handler
    response = ''

    def handle(self):
        """
        request handling happens here
        """
        # empty dummy handler
        self.response = ''

        # raw address+interface, used for requests monitoring
        client_address = deepcopy(self.client_address[0].split('%')[0])
        try:
            interface = socket.if_indextoname(self.client_address[3])
        except OSError:
            # the interface index is 0 if sent to localhost -
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
            if interface not in cfg.INTERFACE and not self.is_control_message:
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
                    if option not in IA_OPTIONS:
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
                    if transaction_id not in transactions:
                        client_llip = decompress_ip6(client_address)
                        transactions[transaction_id] = Transaction(transaction_id,
                                                                   client_llip,
                                                                   interface,
                                                                   message_type,
                                                                   options)
                        # shortcut to transactions[transaction_id]
                        transaction = transactions[transaction_id]
                        # add client MAC address to transaction object
                        if transaction.client_llip in collected_macs and not cfg.IGNORE_MAC:
                            transaction.mac = collected_macs[transaction.client_llip].mac
                    else:
                        # shortcut to transactions[transaction_id]
                        transaction = transactions[transaction_id]
                        transaction.timestamp = timer
                        transaction.last_message_received_type = message_type

                    # log incoming messages
                    log.info('%s | transaction_id: %s%s' % (MESSAGE_TYPES[message_type], transaction.id, transaction.get_options_string()))

                    # 3. answer requests
                    # check if client sent a valid DUID (alphanumeric)
                    if transaction.duid.isalnum():
                        # if request was not addressed to multicast do nothing but logging
                        if transaction.interface == '':
                            log.info('transaction_id: %s | %s' % (transaction.id, 'Multicast necessary but message came from %s' % (colonify_ip6(transaction.client_llip))))
                            # reset transaction counter
                            transaction.counter = 0
                        else:
                            # client will get answer if its LLIP & MAC is known
                            if not transaction.client_llip in collected_macs:
                                if not cfg.IGNORE_MAC:
                                    # complete MAC collection - will make most sence on Linux and its native neighborcache access
                                    collect_macs(timer)

                                    # when still no trace of the client in neighbor cache then send silly signal back
                                    if not transaction.client_llip in collected_macs:
                                        # if not known send status code option failure to get
                                        # LLIP/MAC mapping from neighbor cache
                                        # status code 'Success' sounds silly but works best
                                        self.build_response(MESSAGE_TYPE_REPLY, transaction.id, [13], status=0)
                                        # complete MAC collection
                                        collect_macs(timer)
                                        # if client cannot be found in collected MACs
                                        if not transaction.client_llip in collected_macs:
                                            if cfg.IGNORE_UNKNOWN_CLIENTS and client_address in requests:
                                                if requests[client_address].count > 1:
                                                    requests_blacklist[client_address] = Request(client_address)
                                                    log.info("Blacklisting unknown client {0}".format(client_address))
                                                    return False

                                    # try to add client MAC address to transaction object
                                    try:
                                        transaction.mac = collected_macs[transaction.client_llip].mac
                                    except:
                                        # MAC not yet found :-(
                                        if cfg.LOG_MAC_LLIP:
                                            log.info('transaction_id: %s | %s' % (transaction.id, 'mac address for llip %s unknown' % (colonify_ip6(transaction.client_llip))))

                            # if finally there is some info about the client or MACs play no role try to answer the request
                            if transaction.client_llip in collected_macs or cfg.IGNORE_MAC:
                                if not cfg.IGNORE_MAC:
                                    if transaction.mac == DUMMY_MAC:
                                        transaction.mac = collected_macs[transaction.client_llip].mac

                                # ADVERTISE
                                # if last request was a SOLICIT send an ADVERTISE (type 2) back
                                if transaction.last_message_received_type == 1 \
                                   and transaction.rapid_commit == False:
                                    # preference option (7) is for free
                                    self.build_response(MESSAGE_TYPE_ADVERTISE, transaction.id,
                                                        transaction.ia_options + [7] + transaction.options_request)

                                    # store leases for addresses and lock advertised address
                                    volatile_store.store(deepcopy(transaction), timer)

                                # REQUEST
                                # if last request was a REQUEST (type 3) send a REPLY (type 7) back
                                elif transaction.last_message_received_type == 3 or \
                                     (transaction.last_message_received_type == 1 and
                                      transaction.rapid_commit):
                                    # preference option (7) is for free
                                    # if RapidCommit was set give it back
                                    if not transaction.rapid_commit:
                                        self.build_response(MESSAGE_TYPE_REPLY, transaction.id,
                                                            transaction.ia_options + [7] + transaction.options_request)
                                    else:
                                        self.build_response(MESSAGE_TYPE_REPLY, transaction.id,
                                                            transaction.ia_options + [7] + [14] + transaction.options_request)
                                    # store leases for addresses
                                    volatile_store.store(deepcopy(transaction), timer)

                                    # run external script for setting a route to the delegated prefix
                                    if 25 in transaction.ia_options:
                                        modify_route(transaction.id, 'up')

                                    if cfg.DNS_UPDATE:
                                        dns_update(transaction.id)

                                # CONFIRM
                                # if last request was a CONFIRM (4) send a REPLY (type 7) back
                                # Due to problems with different clients they will get a not-available-reply
                                # but the next ADVERTISE will offer them the last known and still active
                                # lease. This makes sense in case of fixed MAC-based, addresses, ranges and
                                # ID-based addresses, Random addresses will be recalculated
                                elif transaction.last_message_received_type == 4:
                                    # the RFC 3315 is a little bit confusing regarding CONFIRM
                                    # messages so it won't hurt to simply let the client
                                    # solicit addresses again via answering 'NotOnLink'
                                    # thus client is forced in every case to solicit a new address which
                                    # might as well be the old one or a new if prefix has changed
                                    self.build_response(MESSAGE_TYPE_REPLY, transaction.id, [13], status=4)

                                # RENEW
                                # if last request was a RENEW (type 5) send a REPLY (type 7) back
                                elif transaction.last_message_received_type == 5:
                                    self.build_response(MESSAGE_TYPE_REPLY, transaction.id,
                                                        transaction.ia_options + [7] + transaction.options_request)
                                    # store leases for addresses
                                    volatile_store.store(deepcopy(transaction), timer)
                                    if cfg.DNS_UPDATE:
                                        dns_update(transaction.id)

                                # REBIND
                                # if last request was a REBIND (type 6) send a REPLY (type 7) back
                                elif transaction.last_message_received_type == 6:
                                    self.build_response(MESSAGE_TYPE_REPLY, transaction.id,
                                                        transaction.ia_options + [7] +  transaction.options_request)
                                    # store leases for addresses
                                    volatile_store.store(deepcopy(transaction), timer)

                                # RELEASE
                                # if last request was a RELEASE (type 8) send a REPLY (type 7) back
                                elif transaction.last_message_received_type == 8:
                                    #  build client to be able to delete it from DNS
                                    if transaction.client is None:
                                        # transactions[transaction_id].client = build_client(transaction_id)
                                        transaction.client = Client(transaction.id)
                                    if cfg.DNS_UPDATE:
                                        for a in transaction.addresses:
                                            dns_delete(transaction.id, address=a, action='release')
                                    for a in transaction.addresses:
                                        # free lease
                                        volatile_store.release_lease(a, timer)
                                    for p in transaction.prefixes:
                                        # free prefix - without length
                                        volatile_store.release_prefix(p.split('/')[0], timer)
                                        # delete route to formerly requesting client
                                        modify_route(transaction.id, 'down')
                                    # send status code option (type 13) with success (type 0)
                                    self.build_response(MESSAGE_TYPE_REPLY, transaction.id, [13], status=0)

                                # DECLINE
                                # if last request was a DECLINE (type 9) send a REPLY (type 7) back
                                elif transaction.last_message_received_type == 9:
                                    # maybe has to be refined - now only a status code 'NoBinding' is answered
                                    self.build_response(MESSAGE_TYPE_REPLY, transaction.id, [13], status=3)

                                # INFORMATION-REQUEST
                                # if last request was an INFORMATION-REQUEST (type 11) send a REPLY (type 7) back
                                elif transaction.last_message_received_type == 11:
                                    self.build_response(MESSAGE_TYPE_REPLY, transaction.id, transaction.options_request)

                                # general error - statuscode 1 'Failure'
                                else:
                                    # send Status Code Option (type 13) with status code 'UnspecFail'
                                    self.build_response(MESSAGE_TYPE_REPLY, transaction.id, [13], status=1)

                    # count requests of transaction
                    # if there will be too much something went wrong
                    # may be evaluated to reset the whole transaction
                    transaction.counter += 1

        except Exception as err:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            log.error('handle(): %s | Caused by: %s | Transaction: %s' % (str(err), client_address, transaction.id))
            return None

    def build_response(self, message_type_response, transaction_id, options_request, status=0):
        """
            creates answer and puts it into self.handler
            arguments:
                message_type_response - mostly 2 or 7
                transaction_id
                option_request
                status - mostly 0 (OK)
            handler will be sent by self.finish()
        """
        try:
            # shortcut to transactions[transaction_id]
            transaction = transactions[transaction_id]

            # Header
            # handler type + transaction id
            response_ascii = '%02x' % message_type_response
            response_ascii += transaction_id

            # these options are always useful
            # Option 1 client identifier
            response_ascii += build_option(1, transaction.duid)
            # Option 2 server identifier
            response_ascii += build_option(2, cfg.SERVERDUID)

            # list of options in answer to be logged
            options_answer = []

            # IA_NA non-temporary addresses
            # Option 3 + 5 Identity Association for Non-temporary Address
            if 3 in options_request:
                # check if MAC of LLIP is really known
                if transaction.client_llip in collected_macs or cfg.IGNORE_MAC:
                    # collect client information
                    if transaction.client is None:
                        transaction.client = Client(transaction_id)

                    if 'addresses' in cfg.CLASSES[transaction.client.client_class].ADVERTISE and \
                                    (3 or 4) in transaction.ia_options:
                        # check if only a short NoAddrAvail answer or none at all is to be returned
                        if not transaction.answer == 'normal':
                            if transaction.answer == 'noaddress':
                                # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                                response_ascii += build_option(13, '%04x' % 2)
                                # clean client addresses which not be deployed anyway
                                transaction.client.addresses[:] = []
                                # options in answer to be logged
                                options_answer.append(13)
                            else:
                                # clean handler as there is nothing to respond in case of answer = none
                                self.response = ''
                                return None
                        else:
                            # if client could not be built because of database problems send
                            # status message back
                            if transaction.client:
                                # embed option 5 into option 3 - several if necessary
                                ia_addresses = ''
                                try:
                                    for address in transaction.client.addresses:
                                        if address.IA_TYPE == 'na':
                                            ipv6_address = binascii.hexlify(socket.inet_pton(socket.AF_INET6,
                                                                                             colonify_ip6(address.ADDRESS))).decode()
                                            # if a transaction consists of too many requests from client -
                                            # - might be caused by going wild Windows clients -
                                            # reset all addresses with lifetime 0
                                            # lets start with maximal transaction count of 10
                                            if transaction.counter < 10:
                                                preferred_lifetime = '%08x' % int(address.PREFERRED_LIFETIME)
                                                valid_lifetime = '%08x' % int(address.VALID_LIFETIME)
                                            else:
                                                preferred_lifetime = '%08x' % 0
                                                valid_lifetime = '%08x' % 0
                                            ia_addresses += build_option(5, ipv6_address + preferred_lifetime + valid_lifetime)

                                    if not ia_addresses == '':
                                        #
                                        # todo: default clients sometimes seem to have class ''
                                        #
                                        if transaction.client.client_class != '':
                                            t1 = '%08x' % int(cfg.CLASSES[transaction.client.client_class].T1)
                                            t2 = '%08x' % int(cfg.CLASSES[transaction.client.client_class].T2)
                                        else:
                                            t1 = '%08x' % int(cfg.T1)
                                            t2 = '%08x' % int(cfg.T2)

                                        response_ascii += build_option(3, transaction.iaid + t1 + t2 + ia_addresses)
                                    # options in answer to be logged
                                    options_answer.append(3)
                                except:
                                    # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                                    response_ascii += build_option(13, '%04x' % 2)
                                    # options in answer to be logged
                                    options_answer.append(13)
                            else:
                                # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                                response_ascii += build_option(13, '%04x' % 2)
                                # options in answer to be logged
                                options_answer.append(13)

            # IA_TA temporary addresses
            if 4 in options_request:
                # check if MAC of LLIP is really known
                if transaction.client_llip in collected_macs or cfg.IGNORE_MAC:
                    # collect client information
                    if transaction.client is None:
                        # transactions[transaction_id].client = build_client(transaction_id)
                        transaction.client = Client(transaction.id)

                    if 'addresses' in cfg.CLASSES[transaction.client.client_class].ADVERTISE and \
                        (3 or 4) in transaction.ia_options:
                        # check if only a short NoAddrAvail answer or none at all ist t be returned
                        if not transaction.answer == 'normal':
                            if transaction.answer == 'noaddress':
                                # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                                response_ascii += build_option(13, '%04x' % 2)
                                # clean client addresses which not be deployed anyway
                                transaction.client.addresses[:] = []
                                # options in answer to be logged
                                options_answer.append(13)
                            else:
                                # clean handler as there is nothing to respond in case of answer = none
                                self.response = ''
                                return None
                        else:
                            # if client could not be built because of database problems send
                            # status message back
                            if transaction.client:
                                # embed option 5 into option 4 - several if necessary
                                ia_addresses = ''
                                try:
                                    for address in transaction.client.addresses:
                                        if address.IA_TYPE == 'ta':
                                            ipv6_address = binascii.hexlify(socket.inet_pton(socket.AF_INET6,
                                                                                             colonify_ip6(address.ADDRESS))).decode()
                                            # if a transaction consists of too many requests from client -
                                            # - might be caused by going wild Windows clients -
                                            # reset all addresses with lifetime 0
                                            # lets start with maximal transaction count of 10
                                            if transaction.counter < 10:
                                                preferred_lifetime = '%08x' % int(address.PREFERRED_LIFETIME)
                                                valid_lifetime = '%08x' % int(address.VALID_LIFETIME)
                                            else:
                                                preferred_lifetime = '%08x' % 0
                                                valid_lifetime = '%08x' % 0
                                            ia_addresses += build_option(5, ipv6_address + preferred_lifetime + valid_lifetime)
                                    if not ia_addresses == '':
                                        response_ascii += build_option(4, transaction.iaid + ia_addresses)
                                    # options in answer to be logged
                                    options_answer.append(4)
                                except:
                                    # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                                    response_ascii += build_option(13, '%04x' % 2)
                                    # options in answer to be logged
                                    options_answer.append(13)
                            else:
                                # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                                response_ascii += build_option(13, '%04x' % 2)
                                # options in answer to be logged
                                options_answer.append(13)

            # # Option 7 Server Preference
            # if 7 in options_request:
            #     option_7.build(response_ascii=response_ascii,
            #                    options_answer=options_answer)

            # # Option 12 Server Unicast Option
            # if 12 in options_request:
            #     option_12.build(response_ascii=response_ascii,
            #                     options_answer=options_answer)

            # # Option 13 Status Code Option - statuscode is taken from dictionary
            # if 13 in options_request:
            #     option_13.build(response_ascii=response_ascii,
            #                     options_answer=options_answer,
            #                     status=status)

            # # Option 14 Rapid Commit Option - necessary for REPLY to SOLICIT message with Rapid Commit
            # if 14 in options_request:
            #     option_14.build(response_ascii=response_ascii,
            #                     options_answer=options_answer)

            for number in options_request:
                if number in options:
                    options[number].build(response_ascii=response_ascii,
                                          options_answer=options_answer,
                                          status=status)

            # Option 23 DNS recursive name server
            if 23 in options_request:
                option_23.build(response_ascii=response_ascii,
                                options_answer=options_answer,
                                transaction_id=transaction.id)

            # Option 24 Domain Search List
            if 24 in options_request:
                option_24.build(response_ascii=response_ascii,
                                options_answer=options_answer)

            # Option 25 Prefix Delegation
            if 25 in options_request:
                option_25.build(response_ascii=response_ascii,
                                options_answer=options_answer,
                                transaction_id=transaction.id)

            # Option 31 OPTION_SNTP_SERVERS
            if 31 in options_request and cfg.SNTP_SERVERS != '':
                sntp_servers = ''
                for s in cfg.SNTP_SERVERS:
                    sntp_server = binascii.hexlify(socket.inet_pton(socket.AF_INET6, s)).decode()
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
            if 39 in options_request and transaction.client:
                # flags for answer
                N, O, S = 0, 0, 0
                # use hostname supplied by client
                if cfg.DNS_USE_CLIENT_HOSTNAME:
                    hostname = transaction.hostname
                # use hostname from config
                else:
                    hostname = transaction.client.hostname
                if not hostname == '':
                    if cfg.DNS_UPDATE == 1:
                        # DNS update done by server - don't care what client wants
                        if cfg.DNS_IGNORE_CLIENT:
                            S = 1
                            O = 1
                        else:
                            # honor the client's request for the server to initiate DNS updates
                            if transaction.dns_s == 1:
                                S = 1
                            # honor the client's request for no server-initiated DNS update
                            elif transaction.dns_n == 1:
                                N = 1
                    else:
                        # no DNS update at all, not for server and not for client
                        if transaction.dns_n == 1 or\
                           transaction.dns_s == 1:
                            O = 1

                    # sum of flags
                    nos_flags = N*4 + O*2 + S*1

                    response_ascii += build_option(39, '%02x' % nos_flags + convert_dns_to_binary(hostname + '.' + cfg.DOMAIN))
                else:
                    # if no hostname given put something in and force client override
                    response_ascii += build_option(39, '%02x' % 3 + convert_dns_to_binary('invalid-hostname'))
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
                                ntp_server_suboption = build_option(1, binascii.hexlify(socket.inet_pton(socket.AF_INET6, ntp_server)).decode())
                            elif ntp_server_type == 'MC':
                                ntp_server_suboption = build_option(2, binascii.hexlify(socket.inet_pton(socket.AF_INET6, ntp_server)).decode())
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
                if transaction.client is None:
                    transaction.client = Client(transaction.id)

                bootfiles = transaction.client.bootfiles
                if len(bootfiles) > 0:
                    # TODO add preference logic
                    bootfile_url = bootfiles[0].BOOTFILE_URL
                    transaction.client.chosen_boot_file = bootfile_url
                    bootfile_options = binascii.hexlify(bootfile_url).decode()
                    response_ascii += build_option(59, bootfile_options)
                    # options in answer to be logged
                    options_answer.append(59)

            # if databases are not connected send error to client
            if not (config_store.connected == volatile_store.connected == True):
                # mark database errors - every database may add its error
                db_error = []
                if not config_store.connected:
                    db_error.append('config')
                    config_store.db_connect()
                if not volatile_store.connected:
                    db_error.append('volatile')
                    volatile_store.db_connect()

                # create error handler - headers have to be recreated because
                # problems may have arisen while processing and these information
                # is not valid anymore
                # handler type + transaction id
                response_ascii = '%02x' % (7)
                response_ascii += transaction.id

                # always of interest
                # option 1 client identifier
                response_ascii += build_option(1, transaction.duid)
                # option 2 server identifier
                response_ascii += build_option(2, cfg.SERVERDUID)

                # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                response_ascii += build_option(13, '%04x' % 2)

                log.error('%s| transaction_id: %s | DatabaseError: %s' % (MESSAGE_TYPES[message_type_response], transaction.id, ' '.join(db_error)))

            else:
                # log handler
                if not transaction.client is None:
                    if len(transaction.client.addresses) == 0 and\
                       len(transaction.client.prefixes) == 0 and\
                       transaction.answer == 'normal' and\
                       transaction.last_message_received_type in [1, 3, 5, 6]:
                        # create error handler - headers have to be recreated because
                        # problems may have arisen while processing and these information
                        # is not valid anymore
                        # handler type + transaction id
                        response_ascii = '%02x' % 7
                        response_ascii += transaction.id

                        # always of interest
                        # option 1 client identifier
                        response_ascii += build_option(1, transaction.duid)
                        # option 2 server identifier
                        response_ascii += build_option(2, cfg.SERVERDUID)

                        # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                        response_ascii += build_option(13, '%04x' % 2)
                        # options in answer to be logged
                        options_answer.append(13)

                        # log warning message about unavailable addresses
                        log.warning('REPLY | no addresses or prefixes available | transaction_id: %s | client_llip: %s' % \
                                    (transaction.id, colonify_ip6(transaction.client_llip)))

                    elif 3 in options_request or 4 in options_request or 13 in options_request or 25 in options_request:
                        options_answer = sorted(options_answer)
                        log.info('%s | transaction_id: %s | options: %s%s' % (MESSAGE_TYPES[message_type_response],
                                                                              transaction.id,
                                                                              options_answer,
                                                                              transaction.client.get_options_string()))
                    else:
                        print(options_request)
                        log.info('what else should I do?')
                else:
                    options_answer = sorted(options_answer)
                    log.info('%s | transaction_id: %s | options: %s' % (MESSAGE_TYPES[message_type_response],
                                                                        transaction.id,
                                                                        options_answer))

            # handler
            self.response = binascii.unhexlify(response_ascii)

        except Exception as err:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            log.error('handler: ' + str(err))
            # clear any handler
            self.response = ''

            return None

    def finish(self):
        """
        send handler from self.handler
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
