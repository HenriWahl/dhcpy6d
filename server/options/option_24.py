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

from server.config import cfg
from server.helpers import convert_dns_to_binary
from server.options import OptionTemplate


class Option(OptionTemplate):
    """
    Option 24 Domain Search List
    """
    def build(self, **kwargs):
        converted_domain_search_list = ''
        for d in cfg.DOMAIN_SEARCH_LIST:
            converted_domain_search_list += convert_dns_to_binary(d)
        response_ascii_part = self.build_option(self.number, converted_domain_search_list)
        return response_ascii_part, self.number