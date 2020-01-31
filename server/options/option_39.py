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
from server.helpers import convert_dns_to_binary
from server.options import OptionTemplate


class Option(OptionTemplate):
    """
    Option 39 FQDN

    http://tools.ietf.org/html/rfc4704#page-5
    regarding RFC 4704 5. there are 3 kinds of client behaviour for N O S:
      - client wants to update DNS itself -> sends 0 0 0
      - client wants server to update DNS -> sends 0 0 1
       - client wants no server DNS update -> sends 1 0 0
    """
    def build(self, transaction=None, **kwargs):
        # dummy empty return value
        response_ascii_part = ''

        # http://tools.ietf.org/html/rfc4704#page-5
        # regarding RFC 4704 5. there are 3 kinds of client behaviour for N O S:
        # - client wants to update DNS itself -> sends 0 0 0
        # - client wants server to update DNS -> sends 0 0 1
        # - client wants no server DNS update -> sends 1 0 0
        if transaction.client:
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
                    if transaction.dns_n == 1 or \
                            transaction.dns_s == 1:
                        O = 1
                # sum of flags
                nos_flags = N * 4 + O * 2 + S * 1
                fqdn_binary = convert_dns_to_binary(f'{hostname}.{cfg.DOMAIN}')
                response_ascii_part = self.build_option(self.number, f'{nos_flags:02x}{fqdn_binary}')
            else:
                # if no hostname given put something in and force client override
                fqdn_binary = convert_dns_to_binary(f'invalid-hostname.{cfg.DOMAIN}')
                response_ascii_part = self.build_option(self.number, f'{3:02x}{fqdn_binary}')

        return response_ascii_part, self.number
