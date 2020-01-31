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
    Option 31 SNTP Servers
    """
    def build(self, transaction=None, **kwargs):
        # dummy empty return value
        response_ascii_part = ''

        if cfg.SNTP_SERVERS != '':
            sntp_servers = ''
            for s in cfg.SNTP_SERVERS:
                sntp_server = hexlify(inet_pton(AF_INET6, s)).decode()
                sntp_servers += sntp_server
            response_ascii_part = self.build_option(self.number, sntp_servers)

        return response_ascii_part, self.number