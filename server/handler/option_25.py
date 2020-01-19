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
import socket

from ..client import Client
from ..config import cfg
from ..globals import (collected_macs,
                       transactions)
from ..helpers import (build_option,
                       colonify_ip6)


# Option 25 Prefix Delegation
def build(response_ascii=None, transaction_id=None, options_answer=None, response=None):
    # check if MAC of LLIP is really known
    if transactions[transaction_id].client_llip in collected_macs or cfg.IGNORE_MAC:
        # collect client information
        if transactions[transaction_id].client is None:
            transactions[transaction_id].client = Client(transaction_id)

        # Only if prefixes are provided
        if 'prefixes' in cfg.CLASSES[transactions[transaction_id].client.client_class].ADVERTISE:
            # check if only a short NoPrefixAvail answer or none at all is to be returned
            if not transactions[transaction_id].answer == 'normal':
                if transactions[transaction_id].answer == 'noprefix':
                    # Option 13 Status Code Option - statuscode is 6: 'No Prefix available'
                    response_ascii += build_option(13, '%04x' % 6)
                    # clean client prefixes which not be deployed anyway
                    transactions[transaction_id].client.prefixes[:] = []
                    # options in answer to be logged
                    options_answer.append(13)
                else:
                    # clean handler as there is nothing to respond in case of answer = none
                    response = ''
            else:
                # if client could not be built because of database problems send
                # status message back
                if transactions[transaction_id].client:
                    # embed option 26 into option 25 - several if necessary
                    ia_prefixes = ''
                    try:
                        for prefix in transactions[transaction_id].client.prefixes:
                            ipv6_prefix = binascii.hexlify(socket.inet_pton(socket.AF_INET6,
                                                                            colonify_ip6(prefix.PREFIX))).decode()
                            if prefix.VALID:
                                preferred_lifetime = '%08x' % int(prefix.PREFERRED_LIFETIME)
                                valid_lifetime = '%08x' % int(prefix.VALID_LIFETIME)
                            else:
                                preferred_lifetime = '%08x' % 0
                                valid_lifetime = '%08x' % 0
                            length = '%02x' % int(prefix.LENGTH)
                            ia_prefixes += build_option(26, preferred_lifetime + valid_lifetime + length + ipv6_prefix)

                        if transactions[transaction_id].client.client_class != '':
                            t1 = '%08x' % int(cfg.CLASSES[transactions[transaction_id].client.client_class].T1)
                            t2 = '%08x' % int(cfg.CLASSES[transactions[transaction_id].client.client_class].T2)
                        else:
                            t1 = '%08x' % int(cfg.T1)
                            t2 = '%08x' % int(cfg.T2)

                        # even if there anre no prefixes server has to deliver an empty PD
                        response_ascii += build_option(25, transactions[transaction_id].iaid + t1 + t2 + ia_prefixes)
                        # if no prefixes available a NoPrefixAvail status code has to be sent
                        if ia_prefixes == '':
                            # REBIND not possible
                            if transactions[transaction_id].last_message_received_type == 6:
                                # Option 13 Status Code Option - statuscode is 3: 'NoBinding'
                                response_ascii += build_option(13, '%04x' % 3)
                            else:
                                # Option 13 Status Code Option - statuscode is 6: 'No Prefix available'
                                response_ascii += build_option(13, '%04x' % 6)
                        # options in answer to be logged
                        options_answer.append(25)

                    except Exception as err:
                        print(err)
                        # Option 13 Status Code Option - statuscode is 6: 'No Prefix available'
                        response_ascii += build_option(13, '%04x' % 6)
                        # options in answer to be logged
                        options_answer.append(25)
                else:
                    # Option 13 Status Code Option - statuscode is 6: 'No Prefix available'
                    response_ascii += build_option(13, '%04x' % (6))
                    # options in answer to be logged
                    options_answer.append(25)
