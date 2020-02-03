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
    Option 25 Prefix Delegation
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

            # Only if prefixes are provided
            if 'prefixes' in cfg.CLASSES[transaction.client.client_class].ADVERTISE:
                # check if only a short NoPrefixAvail answer or none at all is to be returned
                if not transaction.answer == 'normal':
                    if transaction.answer == 'noprefix':
                        # Option 13 Status Code Option - statuscode is 6: 'No Prefix available'
                        response_ascii_part = self.build_option(CONST.OPTION.STATUS_CODE,
                                                                f'{CONST.STATUS.NO_PREFIX_AVAILABLE:04x}')
                        # clean client prefixes which not be deployed anyway
                        transaction.client.prefixes[:] = []
                        # options in answer to be logged
                        options_answer_part = self.number
                else:
                    # if client could not be built because of database problems send
                    # status message back
                    if transaction.client:
                        # embed option 26 into option 25 - several if necessary
                        ia_prefixes = ''
                        try:
                            for prefix in transaction.client.prefixes:
                                ipv6_prefix = hexlify(inet_pton(AF_INET6, colonify_ip6(prefix.PREFIX))).decode()
                                if prefix.VALID:
                                    preferred_lifetime = f'{int(prefix.PREFERRED_LIFETIME):08x}'
                                    valid_lifetime = f'{int(prefix.VALID_LIFETIME):08x}'
                                else:
                                    preferred_lifetime = f'{0:08x}'
                                    valid_lifetime = f'{0:08x}'
                                length = f'{int(prefix.LENGTH):02x}'
                                ia_prefixes += self.build_option(CONST.OPTION.IAPREFIX,
                                                                 preferred_lifetime +
                                                                 valid_lifetime +
                                                                 length +
                                                                 ipv6_prefix)

                            if transaction.client.client_class != '':
                                t1 = f'{int(cfg.CLASSES[transaction.client.client_class].T1):08x}'
                                t2 = f'{int(cfg.CLASSES[transaction.client.client_class].T2):08x}'
                            else:
                                t1 = f'{int(cfg.T1):08x}'
                                t2 = f'{int(cfg.T2):08x}'

                            # even if there are no prefixes server has to deliver an empty PD
                            response_ascii_part = self.build_option(self.number, transaction.iaid + t1 + t2 + ia_prefixes)
                            # if no prefixes available a NoPrefixAvail status code has to be sent
                            if ia_prefixes == '':
                                # REBIND not possible
                                if transaction.last_message_received_type == CONST.MESSAGE.REBIND:
                                    # Option 13 Status Code Option - statuscode is 3: 'NoBinding'
                                    response_ascii_part += self.build_option(CONST.OPTION.STATUS_CODE,
                                                                             f'{CONST.STATUS.NO_BINDING:04x}')
                                else:
                                    # Option 13 Status Code Option - statuscode is 6: 'No Prefix available'
                                    response_ascii_part += self.build_option(CONST.OPTION.STATUS_CODE,
                                                                             f'{CONST.STATUS.NO_PREFIX_AVAILABLE:04x}')
                            # options in answer to be logged
                            options_answer_part = self.number

                        except Exception as err:
                            print(err)
                            # Option 13 Status Code Option - statuscode is 6: 'No Prefix available'
                            response_ascii_part = self.build_option(CONST.OPTION.STATUS_CODE,
                                                                    f'{CONST.STATUS.NO_PREFIX_AVAILABLE:04x}')
                            # options in answer to be logged
                            options_answer_part = self.number
                    else:
                        # Option 13 Status Code Option - statuscode is 6: 'No Prefix available'
                        response_ascii_part = self.build_option(CONST.OPTION.STATUS_CODE,
                                                                f'{CONST.STATUS.NO_PREFIX_AVAILABLE:04x}')
                        # options in answer to be logged
                        options_answer_part = self.number

        return response_ascii_part, options_answer_part
