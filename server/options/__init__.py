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

import importlib
import pathlib
import re

from ..config import cfg


class OptionTemplate:
    number = 0
    cfg = cfg

    def __init__(self, number):
        self.number = number

    def build(self, **kwargs):
        pass

    def build_option(self, number, payload):
        """
        glue option with payload
        """
        # option number and length take 2 byte each so the string has to be 4 chars long
        option = f'{number:04x}'  # option number
        option += f'{(len(payload)//2):04x}'  # payload length, /2 because 2 chars are 1 byte
        option += payload
        return option


# globally available options
options = {}
options_path = pathlib.Path(__file__).parent
pattern = re.compile('option_[0-9]{1,3}$')

for path in options_path.glob('option_*.py'):
    name = path.name.rstrip(path.suffix)
    if re.match(pattern, name):
        spec = importlib.util.spec_from_file_location(name, path)
        option = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(option)
        number = int(name.split('_')[1])
        options[number] = option.Option(number)

for option in options.values():
    print(dir(option))

pass