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

import importlib.util
import pathlib
import re


class OptionTemplate:
    """
    Template to be used by derived options - default and custom ones
    """
    number = 0

    def __init__(self, number):
        self.number = number

    def build(self, **kwargs):
        """
        to be filled with life by every single option
        every option has its special treatment of input and output data
        return default dummy values
        """
        return '', False

    def apply(self, **kwargs):
        """
        to be filled with life by every single option
        every transaction has the opportunity to add options, depending on request
        """
        pass

    @staticmethod
    def convert_to_string(number, payload):
        """
        glue option number with payload
        """
        # option number and length take 2 byte each so the string has to be 4 chars long
        option = f'{number:04x}'  # option number
        option += f'{(len(payload)//2):04x}'  # payload length, /2 because 2 chars are 1 byte
        option += payload
        return option


# globally available options
OPTIONS = {}
options_path = pathlib.Path(__file__).parent
pattern = re.compile('option_[0-9]{1,3}$')

# get all option files in path and put them into options dict
for path in options_path.glob('option_*.py'):
    # get rid of ".py" because this suffix won't be in option dict anyway
    name = path.name.rstrip(path.suffix)
    if re.match(pattern, name):
        # load option module
        spec = importlib.util.spec_from_file_location(name, path)
        option = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(option)
        number = int(name.split('_')[1])
        # add to global options constant
        OPTIONS[number] = option.Option(number)
