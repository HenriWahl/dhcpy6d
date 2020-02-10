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

from dhcpy6d.client import Client
from dhcpy6d.helpers import build_option
from dhcpy6d.options import OptionTemplate


class Option(OptionTemplate):
    """
    Option 59 Network Boot
    https://tools.ietf.org/html/rfc5970
    """
    def build(self, transaction=None, **kwargs):
        # dummy empty defaults
        response_string_part = ''
        options_answer_part = None

        # build client if not done yet
        if transaction.client is None:
            transaction.client = Client(transaction)

        bootfiles = transaction.client.bootfiles
        if len(bootfiles) > 0:
            # TODO add preference logic
            bootfile_url = bootfiles[0].BOOTFILE_URL
            transaction.client.chosen_boot_file = bootfile_url
            bootfile_options = hexlify(bootfile_url).decode()
            response_string_part += build_option(self.number, bootfile_options)
            # options in answer to be logged
            options_answer_part = self.number

        return response_string_part, options_answer_part
