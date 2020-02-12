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

from dhcpy6d import collected_macs
from dhcpy6d.client import Client
from dhcpy6d.config import cfg
from dhcpy6d.constants import CONST
from dhcpy6d.helpers import colonify_ip6
from dhcpy6d.options import OptionTemplate


class Option(OptionTemplate):
    """
    Option 4 + 5 Identity Association for Temporary Address
    """
    def build(self, transaction=None, **kwargs):
        # dummy empty defaults
        response_string_part = ''
        options_answer_part = None

        # check if MAC of LLIP is really known
        if transaction.client_llip in collected_macs or cfg.IGNORE_MAC:
            # collect client information
            if transaction.client is None:
                transaction.client = Client(transaction)

            if 'addresses' in cfg.CLASSES[transaction.client.client_class].ADVERTISE and \
                    CONST.OPTION.IA_TA in transaction.ia_options:
                # check if only a short NoAddrAvail answer or none at all ist t be returned
                if not transaction.answer == 'normal':
                    if transaction.answer == 'noaddress':
                        # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                        response_string_part = self.convert_to_string(CONST.OPTION.STATUS_CODE,
                                                                      f'{CONST.STATUS.NO_ADDRESSES_AVAILABLE:04x}')
                        # clean client addresses which not be deployed anyway
                        transaction.client.addresses[:] = []
                        # options in answer to be logged
                        options_answer_part = CONST.OPTION.STATUS_CODE
                else:
                    # if client could not be built because of database problems send
                    # status message back
                    if transaction.client:
                        # embed option 5 into option 4 - several if necessary
                        ia_addresses = ''
                        try:
                            for address in transaction.client.addresses:
                                if address.IA_TYPE == 'ta':
                                    ipv6_address = hexlify(inet_pton(AF_INET6, colonify_ip6(address.ADDRESS))).decode()
                                    # if a transaction consists of too many requests from client -
                                    # - might be caused by going wild Windows clients -
                                    # reset all addresses with lifetime 0
                                    # lets start with maximal transaction count of 10
                                    if transaction.counter < 10:
                                        preferred_lifetime = f'{int(address.PREFERRED_LIFETIME):08x}'
                                        valid_lifetime = f'{int(address.VALID_LIFETIME):08x}'
                                    else:
                                        preferred_lifetime = '00000000'
                                        valid_lifetime = '00000000'
                                    ia_addresses += self.convert_to_string(CONST.OPTION.IAADDR,
                                                                           ipv6_address +
                                                                           preferred_lifetime +
                                                                           valid_lifetime)
                            if ia_addresses != '':
                                response_string_part = self.convert_to_string(CONST.OPTION.IA_TA,
                                                                              transaction.iaid +
                                                                              ia_addresses)
                            # options in answer to be logged
                            options_answer_part = CONST.OPTION.IA_TA
                        except:
                            # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                            response_string_part = self.convert_to_string(CONST.OPTION.STATUS_CODE,
                                                                          f'{CONST.STATUS.NO_ADDRESSES_AVAILABLE:04x}')
                            # options in answer to be logged
                            options_answer_part = CONST.OPTION.STATUS_CODE
                    else:
                        # Option 13 Status Code Option - statuscode is 2: 'No Addresses available'
                        response_string_part = self.convert_to_string(CONST.OPTION.STATUS_CODE,
                                                                      f'{CONST.STATUS.NO_ADDRESSES_AVAILABLE:04x}')
                        # options in answer to be logged
                        options_answer_part = CONST.OPTION.STATUS_CODE

        return response_string_part, options_answer_part

    def apply(self, transaction=None, option=None, **kwargs):
        """
        IA TA addresses of client
        """
        for payload in option:
            transaction.iaid = payload[0:8]
            transaction.iat1 = int(payload[8:16], 16)
            transaction.iat2 = int(payload[16:24], 16)

            # addresses given by client if any
            for a in range(len(payload[32:]) // 44):
                address = payload[32:][(a * 56):(a * 56) + 32]
                # in case an address is asked for twice by one host ignore the twin
                if address not in transaction.addresses:
                    transaction.addresses.append(address)
        transaction.ia_options.append(CONST.OPTION.IA_TA)
