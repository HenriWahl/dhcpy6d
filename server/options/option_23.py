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

from server.config import cfg
from server.options import OptionTemplate


class Option(OptionTemplate):
    """
    Option 23 DNS recursive name server
    """
    def build(self, response_ascii=None, options_answer=None, transaction=None, **kwargs):
        # should not be necessary to check if Transactions[transaction_id].client exists but there are
        # crazy clients out in the wild which might become silent this way
        if transaction.client:
            if len(cfg.CLASSES[transaction.client.client_class].NAMESERVER) > 0:
                nameserver = ''
                for ns in cfg.CLASSES[transaction.client.client_class].NAMESERVER:
                    nameserver += inet_pton(AF_INET6, ns)
                response_ascii += self.build_option(self.number, hexlify(nameserver).decode())
                options_answer.append(self.number)

        elif len(cfg.NAMESERVER) > 0:
            # in case several nameservers are given convert them all and add them
            nameserver = ''
            for ns in cfg.NAMESERVER:
                nameserver += inet_pton(AF_INET6, ns)
            response_ascii += self.build_option(self.number, hexlify(nameserver).decode())
            options_answer.append(self.number)