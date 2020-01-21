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
from server.options import OptionTemplate


class Option(OptionTemplate):
    """
    Option 7 Server Preference
    """
    def build(self, options_answer=None, **kwargs):
        response_ascii_part = self.build_option(self.number, f'{int(cfg.SERVER_PREFERENCE):02x}')
        options_answer.append(self.number)
        return response_ascii_part
