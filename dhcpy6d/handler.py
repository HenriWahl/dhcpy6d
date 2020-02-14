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

from .client import Client
from .config import cfg
from .constants import CONST
from .domain import (dns_delete,
                     dns_update)
from .globals import (collected_macs,
                      DUMMY_MAC,
                      IA_OPTIONS,
                      requests,
                      requests_blacklist,
                      timer,
                      transactions)
from .helpers import (build_option,
                      colonify_ip6,
                      decompress_ip6,
                      LOCALHOST,
                      LOCALHOST_INTERFACES)
from .log import log
from .macs import collect_macs
from .options import OPTIONS
from .route import modify_route
from .storage import (config_store,
                      volatile_store)
from .transaction import Transaction


class Request:
    """
        to be stored in requests dictionary to log client requests to be able to find brute force clients
    """
    def __init__(self, client):
        self.client = client
        self.count = 1
        self.timestamp = timer.time


class RequestHandler(socketserver.DatagramRequestHandler):
    """
        manage all incoming datagrams, builds clients from config and previous leases
    """
    # empty dummy handler
    response = ''
    # most messages are no locally generated control messages
    is_control_message = False

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
                if message_type in CONST.MESSAGE_DICT:
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
                        transaction.timestamp = timer.time
                        transaction.last_message_received_type = message_type

                    # log incoming messages
                    log.info(f'{CONST.MESSAGE_DICT[message_type]} | '
                             f'transaction: {transaction.id}{transaction.get_options_string()}')

                    # 3. answer requests
                    # check if client sent a valid DUID (alphanumeric)
                    if transaction.duid.isalnum():
                        # if request was not addressed to multicast do nothing but logging
                        if transaction.interface == '':
                            log.info(f'transaction: {transaction.id} | Multicast necessary '
                                     f'but message came from {colonify_ip6(transaction.client_llip)}')
                            # reset transaction counter
                            transaction.counter = 0
                        else:
                            # client will get answer if its LLIP & MAC is known
                            if transaction.client_llip not in collected_macs:
                                if not cfg.IGNORE_MAC:
                                    # complete MAC collection - will make most sense on Linux
                                    # and its native neighborcache access
                                    collect_macs(timer.time)

                                    # when still no trace of the client in neighbor cache then send silly signal back
                                    if transaction.client_llip not in collected_macs:
                                        # if not known send status code option failure to get
                                        # LLIP/MAC mapping from neighbor cache
                                        # status code 'Success' sounds silly but works best
                                        self.build_response(CONST.MESSAGE.REPLY,
                                                            transaction,
                                                            [CONST.OPTION.STATUS_CODE],
                                                            status=CONST.STATUS.SUCCESS)
                                        # complete MAC collection
                                        collect_macs(timer.time)
                                        # if client cannot be found in collected MACs
                                        if transaction.client_llip not in collected_macs:
                                            if cfg.IGNORE_UNKNOWN_CLIENTS and client_address in requests:
                                                if requests[client_address].count > 1:
                                                    requests_blacklist[client_address] = Request(client_address)
                                                    log.info(f"Blacklisting unknown client {client_address}")
                                                    return False

                                    # try to add client MAC address to transaction object
                                    try:
                                        transaction.mac = collected_macs[transaction.client_llip].mac
                                    except KeyError:
                                        # MAC not yet found :-(
                                        if cfg.LOG_MAC_LLIP:
                                            log.info(f'transaction: {transaction.id} | mac address for '
                                                     f'llip {colonify_ip6(transaction.client_llip)} unknown')

                            # if finally there is some info about the client or MACs
                            # it plays no role try to answer the request
                            if transaction.client_llip in collected_macs or cfg.IGNORE_MAC:
                                if not cfg.IGNORE_MAC:
                                    if transaction.mac == DUMMY_MAC:
                                        transaction.mac = collected_macs[transaction.client_llip].mac

                                # ADVERTISE
                                # if last request was a SOLICIT send an ADVERTISE (type 2) back
                                if transaction.last_message_received_type == CONST.MESSAGE.SOLICIT \
                                   and not transaction.rapid_commit:
                                    # preference option (7) is for free
                                    self.build_response(CONST.MESSAGE.ADVERTISE,
                                                        transaction,
                                                        transaction.ia_options +
                                                        [CONST.OPTION.PREFERENCE] +
                                                        transaction.options_request)

                                    # store leases for addresses and lock advertised address
                                    volatile_store.store(deepcopy(transaction), timer.time)

                                # REQUEST
                                # if last request was a REQUEST (type 3) send a REPLY (type 7) back
                                elif transaction.last_message_received_type == CONST.MESSAGE.REQUEST or \
                                    (transaction.last_message_received_type == CONST.MESSAGE.SOLICIT and
                                     transaction.rapid_commit):
                                    # preference option (7) is for free
                                    # if RapidCommit was set give it back
                                    if not transaction.rapid_commit:
                                        self.build_response(CONST.MESSAGE.REPLY,
                                                            transaction,
                                                            transaction.ia_options +
                                                            [CONST.OPTION.PREFERENCE] +
                                                            transaction.options_request)
                                    else:
                                        self.build_response(CONST.MESSAGE.REPLY,
                                                            transaction,
                                                            transaction.ia_options +
                                                            [CONST.OPTION.PREFERENCE] +
                                                            [CONST.OPTION.RAPID_COMMIT] + transaction.options_request)
                                    # store leases for addresses
                                    volatile_store.store(deepcopy(transaction), timer.time)

                                    # run external script for setting a route to the delegated prefix
                                    if CONST.OPTION.IA_PD in transaction.ia_options:
                                        modify_route(transaction, 'up')

                                    if cfg.DNS_UPDATE:
                                        dns_update(transaction)

                                # CONFIRM
                                # if last request was a CONFIRM (4) send a REPLY (type 7) back
                                # Due to problems with different clients they will get a not-available-reply
                                # but the next ADVERTISE will offer them the last known and still active
                                # lease. This makes sense in case of fixed MAC-based, addresses, ranges and
                                # ID-based addresses, Random addresses will be recalculated
                                elif transaction.last_message_received_type == CONST.MESSAGE.CONFIRM:
                                    # the RFC 3315 is a little bit confusing regarding CONFIRM
                                    # messages so it won't hurt to simply let the client
                                    # solicit addresses again via answering 'NotOnLink'
                                    # thus client is forced in every case to solicit a new address which
                                    # might as well be the old one or a new if prefix has changed
                                    self.build_response(CONST.MESSAGE.REPLY,
                                                        transaction,
                                                        [CONST.OPTION.STATUS_CODE],
                                                        status=CONST.STATUS.PREFIX_NOT_APPROPRIATE_FOR_LINK)

                                # RENEW
                                # if last request was a RENEW (type 5) send a REPLY (type 7) back
                                elif transaction.last_message_received_type == CONST.MESSAGE.RENEW:
                                    self.build_response(CONST.MESSAGE.REPLY,
                                                        transaction,
                                                        transaction.ia_options +
                                                        [CONST.OPTION.PREFERENCE] +
                                                        transaction.options_request)
                                    # store leases for addresses
                                    volatile_store.store(deepcopy(transaction), timer.time)
                                    if cfg.DNS_UPDATE:
                                        dns_update(transaction)

                                # REBIND
                                # if last request was a REBIND (type 6) send a REPLY (type 7) back
                                elif transaction.last_message_received_type == CONST.MESSAGE.REBIND:
                                    self.build_response(CONST.MESSAGE.REPLY,
                                                        transaction,
                                                        transaction.ia_options +
                                                        [CONST.OPTION.PREFERENCE] +
                                                        transaction.options_request)
                                    # store leases for addresses
                                    volatile_store.store(deepcopy(transaction), timer.time)

                                # RELEASE
                                # if last request was a RELEASE (type 8) send a REPLY (type 7) back
                                elif transaction.last_message_received_type == CONST.MESSAGE.RELEASE:
                                    #  build client to be able to delete it from DNS
                                    if transaction.client is None:
                                        transaction.client = Client(transaction)
                                    if cfg.DNS_UPDATE:
                                        for a in transaction.addresses:
                                            dns_delete(transaction, address=a, action='release')
                                    for a in transaction.addresses:
                                        # free lease
                                        volatile_store.release_lease(a, timer.time)
                                    for p in transaction.prefixes:
                                        # free prefix - without length
                                        volatile_store.release_prefix(p.split('/')[0], timer.time)
                                        # delete route to formerly requesting client
                                        modify_route(transaction, 'down')
                                    # send status code option (type 13) with success (type 0)
                                    self.build_response(CONST.MESSAGE.REPLY,
                                                        transaction,
                                                        [CONST.OPTION.STATUS_CODE],
                                                        status=CONST.STATUS.SUCCESS)

                                # DECLINE
                                # if last request was a DECLINE (type 9) send a REPLY (type 7) back
                                elif transaction.last_message_received_type == CONST.MESSAGE.DECLINE:
                                    # maybe has to be refined - now only a status code 'NoBinding' is answered
                                    self.build_response(CONST.MESSAGE.REPLY,
                                                        transaction,
                                                        [CONST.OPTION.STATUS_CODE],
                                                        status=CONST.STATUS.NO_BINDING)

                                # INFORMATION-REQUEST
                                # if last request was an INFORMATION-REQUEST (type 11) send a REPLY (type 7) back
                                elif transaction.last_message_received_type == CONST.MESSAGE.INFORMATION_REQUEST:
                                    self.build_response(CONST.MESSAGE.REPLY,
                                                        transaction,
                                                        transaction.options_request)

                                # general error - statuscode 1 'Failure'
                                else:
                                    # send Status Code Option (type 13) with status code 'UnspecFail'
                                    self.build_response(CONST.MESSAGE.REPLY,
                                                        transaction,
                                                        [CONST.OPTION.STATUS_CODE],
                                                        status=CONST.STATUS.FAILURE)

                    # count requests of transaction
                    # if there will be too much something went wrong
                    # may be evaluated to reset the whole transaction
                    transaction.counter += 1

        except Exception as err:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            log.error(f'handle(): {str(err)} | caused by: {client_address} | transaction: {transaction.id}')
            return None

    def build_response(self, message_type_response, transaction, options_request, status=0):
        """
            creates answer and puts it into self.handler
            arguments:
                message_type_response - mostly 2 or 7
                transaction
                option_request
                status - mostly 0 (OK)
            handler will be sent by self.finish()
        """
        try:
            # # shortcut to transactions[transaction_id]
            # transaction = transactions[transaction_id]

            # should be asked before any responses are built
            if transaction.answer == 'none':
                self.response = ''
                return None

            # Header
            # handler type + transaction id
            response_string = f'{message_type_response:02x}'
            response_string += transaction.id

            # these options are always useful
            # Option 1 client identifier
            response_string += build_option(CONST.OPTION.CLIENTID, transaction.duid)
            # Option 2 server identifier
            response_string += build_option(CONST.OPTION.SERVERID, cfg.SERVERDUID)

            # list of options in answer to be logged
            options_answer = []

            # build all requested options if they are handled
            for number in options_request:
                if number in OPTIONS:
                    try:
                        response_string_part, options_answer_part = OPTIONS[number].build(transaction=transaction,
                                                                                          status=status)
                        response_string += response_string_part
                        if options_answer_part:
                            options_answer.append(options_answer_part)
                    except Exception:
                        traceback.print_exc(file=sys.stdout)
                        sys.stdout.flush()

            # if databases are not connected send error to client
            # if not (config_store.connected == volatile_store.connected == True):
            if not config_store.connected and not volatile_store.connected:
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
                response_string = f'{CONST.MESSAGE.REPLY:02x}'
                response_string += transaction.id

                # always of interest
                # option 1 client identifier
                response_string += build_option(CONST.OPTION.CLIENTID,
                                                transaction.duid)
                # option 2 server identifier
                response_string += build_option(CONST.OPTION.SERVERID,
                                                cfg.SERVERDUID)

                # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                response_string += build_option(CONST.OPTION.STATUS_CODE,
                                                f'{CONST.STATUS.NO_ADDRESSES_AVAILABLE:04x}')

                log.error(f'{CONST.MESSAGE_DICT[message_type_response]} | '
                          f'transaction: {transaction.id} | '
                          f'DatabaseError: {" ".join(db_error)}')
            else:
                # log handler
                if not transaction.client is None:
                    if len(transaction.client.addresses) == 0 and \
                       len(transaction.client.prefixes) == 0 and \
                       transaction.answer == 'normal' and \
                       transaction.last_message_received_type in [CONST.MESSAGE.SOLICIT,
                                                                  CONST.MESSAGE.REQUEST,
                                                                  CONST.MESSAGE.RENEW,
                                                                  CONST.MESSAGE.REBIND]:
                        # create error handler - headers have to be recreated because
                        # problems may have arisen while processing and these information
                        # is not valid anymore
                        # handler type + transaction id
                        response_string = f'{CONST.MESSAGE.REPLY:02x}'
                        response_string += transaction.id

                        # always of interest
                        # option 1 client identifier
                        response_string += build_option(CONST.OPTION.CLIENTID,
                                                        transaction.duid)
                        # option 2 server identifier
                        response_string += build_option(CONST.OPTION.SERVERID,
                                                        cfg.SERVERDUID)

                        # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                        response_string += build_option(CONST.OPTION.STATUS_CODE,
                                                        f'{CONST.STATUS.NO_ADDRESSES_AVAILABLE:04x}')
                        # options in answer to be logged
                        options_answer.append(CONST.OPTION.STATUS_CODE)

                        # log warning message about unavailable addresses
                        log.warning(f'REPLY | no addresses or prefixes available | '
                                    'transaction: {transaction.id} | '
                                    'client_llip: {colonify_ip6(transaction.client_llip))}')

                    elif CONST.OPTION.IA_NA in options_request or \
                            CONST.OPTION.IA_TA in options_request or \
                            CONST.OPTION.IA_PD in options_request or \
                            CONST.OPTION.STATUS_CODE in options_request:
                        options_answer = sorted(options_answer)
                        log.info(f'{CONST.MESSAGE_DICT[message_type_response]} | '
                                 f'transaction: {transaction.id} | '
                                 f'options: {options_answer} {transaction.client.get_options_string()}')
                    else:
                        print(options_request)
                        log.info('what else should I do?')
                else:
                    options_answer = sorted(options_answer)
                    log.info(f'{CONST.MESSAGE_DICT[message_type_response]} | '
                             f'transaction: {transaction.id} | '
                             f'options: {options_answer}')
            # handler
            self.response = binascii.unhexlify(response_string)

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

    @staticmethod
    def control_message(raw_bytes):
        """
        execute commands sent in by control message
        @staticmethod proposed by PyCharm
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
        log.info(f'Control message \'{" ".join(control_message_clean)}\' received')
