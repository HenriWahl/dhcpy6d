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

from binascii import hexlify
from socket import (AF_INET6,
                    inet_pton)

from server import collected_macs
from server.client import Client
from server.config import cfg
from server.constants import CONST
from server.helpers import colonify_ip6
from server.options import OptionTemplate


class Option(OptionTemplate):
    """
    Option 3 + 5 Identity Association for Non-temporary Address
    """
    def build(self, transaction=None, **kwargs):
        # dummy empty defaults
        response_ascii_part = ''
        options_answer_part = None

        # check if MAC of LLIP is really known
        if transaction.client_llip in collected_macs or cfg.IGNORE_MAC:
            # collect client information
            if transaction.client is None:
                transaction.client = Client(transaction.id)

            if 'addresses' in cfg.CLASSES[transaction.client.client_class].ADVERTISE and \
                    (CONST.OPTION.IA_NA or CONST.OPTION.IA_TA) in transaction.ia_options:
                # check if only a short NoAddrAvail answer or none at all is to be returned
                if not transaction.answer == 'normal':
                    if transaction.answer == 'noaddress':
                        # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                        response_ascii_part = self.build_option(CONST.OPTION.STATUS_CODE,
                                                                f'{CONST.STATUS.NO_ADDRESSES_AVAILABLE:04x}')
                        # clean client addresses which not be deployed anyway
                        transaction.client.addresses[:] = []
                        # options in answer to be logged
                        options_answer_part = CONST.OPTION.STATUS_CODE
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
                                                                                     colonify_ip6(
                                                                                         address.ADDRESS))).decode()
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
                                    ia_addresses += build_option(5,
                                                                 ipv6_address + preferred_lifetime + valid_lifetime)

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

        return response_ascii_part, options_answer_part
