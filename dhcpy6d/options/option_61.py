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

from dhcpy6d.constants import CONST
from dhcpy6d.options import OptionTemplate


class Option(OptionTemplate):
    """
    61 Client System Architecture Type
    """
    def apply(self, transaction=None, option=None, **kwargs):
        # raw client architecture is supplied as a 16-bit integer (e. g. 0007)
        # See https://tools.ietf.org/html/rfc4578#section-2.1
        transaction.client_architecture = option
        # short number (0007 => 7 for dictionary usage)
        client_architecture_short = int(transaction.client_architecture)
        if client_architecture_short in CONST.ARCHITECTURE_TYPE_DICT:
            transaction.known_client_architecture = CONST.ARCHITECTURE_TYPE_DICT[client_architecture_short]
