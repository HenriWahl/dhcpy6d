# DHCPy6d DHCPv6 Daemon
#
# Copyright (C) 2009-2023 Henri Wahl <henri@dhcpy6d.de>
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

class StoreSchema:
    supported_versions = [1, 2]

    version = 1

    @staticmethod
    def set_version(version):
        if version not in StoreSchema.supported_versions:
            raise Exception('Unsupported store schema version %d.' % version)

        StoreSchema.version = version

    @staticmethod
    def get_host_table_fields():
        # The elements in fields will be passed unquoted to SQL queries, NEVER use any user input here!
        fields = ['hostname', 'mac', 'duid', 'class', 'address', 'prefix', 'id']

        if StoreSchema.version >= 2:
            fields += ['prefix_route_link_local']

        return fields
