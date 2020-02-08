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

from dhcpy6d.config import cfg
from dhcpy6d.helpers import convert_dns_to_binary
from dhcpy6d.options import OptionTemplate


class Option(OptionTemplate):
    """
    Option 56 NTP server
    https://tools.ietf.org/html/rfc5908
    """
    def build(self, **kwargs):
        # dummy empty defaults
        response_string_part = ''
        options_answer_part = None

        ntp_server_options = ''
        if len(cfg.NTP_SERVER) > 0:
            for ntp_server_type in list(cfg.NTP_SERVER_dict.keys()):
                # ntp_server_suboption
                for ntp_server in cfg.NTP_SERVER_dict[ntp_server_type]:
                    ntp_server_suboption = ''
                    if ntp_server_type == 'SRV':
                        ntp_server_suboption = self.convert_to_string(1, hexlify(inet_pton(AF_INET6, ntp_server)).decode())
                    elif ntp_server_type == 'MC':
                        ntp_server_suboption = self.convert_to_string(2, hexlify(inet_pton(AF_INET6, ntp_server)).decode())
                    elif ntp_server_type == 'FQDN':
                        ntp_server_suboption = self.convert_to_string(3, convert_dns_to_binary(ntp_server))
                    ntp_server_options += ntp_server_suboption
            response_string_part = self.convert_to_string(self.number, ntp_server_options)
            # options in answer to be logged
            options_answer_part = self.number

        return response_string_part, options_answer_part
