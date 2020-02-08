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

from dhcpy6d.options import OptionTemplate


class Option(OptionTemplate):
    """
    Option 1 Client Identifier Option
    """
    def apply(self, transaction=None, option=None, **kwargs):
        transaction.duid = option
        # See https://github.com/HenriWahl/dhcpy6d/issues/25 and DUID type is not used at all so just remove it
        # self.DUIDType = int(options[1][0:4], 16)
        # # DUID-EN can be retrieved from DUID
        # if self.DUIDType == 2:
        #     # some HP printers seem to produce pretty bad requests, thus some cleaning is necessary
        #     # e.g. '1 1 1 00020000000b0026b1f72a49' instead of '00020000000b0026b1f72a49'
        #     self.DUID_EN = int(options[1].split(' ')[-1][4:12], 16)
