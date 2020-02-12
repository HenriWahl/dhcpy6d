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

import re

from dhcpy6d.config import cfg
from dhcpy6d.helpers import (convert_binary_to_dns,
                             convert_dns_to_binary)
from dhcpy6d.options import OptionTemplate


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
        response_string_part = ''
        options_answer_part = None

        # http://tools.ietf.org/html/rfc4704#page-5
        # regarding RFC 4704 5. there are 3 kinds of client behaviour for N O S:
        # - client wants to update DNS itself -> sends 0 0 0
        # - client wants server to update DNS -> sends 0 0 1
        # - client wants no server DNS update -> sends 1 0 0
        if transaction.client:
            # flags for answer
            n, o, s = 0, 0, 0
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
                        s = 1
                        o = 1
                    else:
                        # honor the client's request for the server to initiate DNS updates
                        if transaction.dns_s == 1:
                            s = 1
                        # honor the client's request for no server-initiated DNS update
                        elif transaction.dns_n == 1:
                            n = 1
                else:
                    # no DNS update at all, not for server and not for client
                    if transaction.dns_n == 1 or \
                            transaction.dns_s == 1:
                        o = 1
                # sum of flags
                nos_flags = n * 4 + o * 2 + s * 1
                fqdn_binary = convert_dns_to_binary(f'{hostname}.{cfg.DOMAIN}')
                response_string_part = self.convert_to_string(self.number, f'{nos_flags:02x}{fqdn_binary}')
            else:
                # if no hostname given put something in and force client override
                fqdn_binary = convert_dns_to_binary('invalid-hostname.{cfg.DOMAIN}')
                response_string_part = self.convert_to_string(self.number, f'{3:02x}{fqdn_binary}')
            # options in answer to be logged
            options_answer_part = self.number

        return response_string_part, options_answer_part

    def apply(self, transaction=None, option=None, **kwargs):
        bits = f'{int(option[1:2]):04d}'
        transaction.dns_n = int(bits[1])
        transaction.dns_o = int(bits[2])
        transaction.dns_s = int(bits[3])
        # only hostname needed
        transaction.fqdn = convert_binary_to_dns(option[2:])
        transaction.hostname = transaction.fqdn.split('.')[0].lower()
        # test if hostname is valid
        hostname_pattern = re.compile('^([a-z0-9-_]+)*$')
        if hostname_pattern.match(transaction.hostname) is None:
            transaction.hostname = ''
        del hostname_pattern
