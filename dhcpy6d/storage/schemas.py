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

# put SQL schemas here to be in reach of all storage types
# generic mostly usable for SQLite and MySQL/MariaDB
GENERIC_SCHEMA = {}
GENERIC_SCHEMA['meta'] = '''
                    CREATE TABLE meta (
                    item_key varchar(255) NOT NULL,
                    item_value varchar(255) NOT NULL,
                    PRIMARY KEY (item_key)
                    );
                    INSERT INTO meta (item_key, item_value) VALUES ('version', '3');
                    '''
GENERIC_SCHEMA['leases'] = '''
                    CREATE TABLE leases (
                    address varchar(32) NOT NULL,
                    active tinyint(4) NOT NULL,
                    preferred_lifetime int(11) NOT NULL,
                    valid_lifetime int(11) NOT NULL,
                    hostname varchar(255) NOT NULL,
                    type varchar(255) NOT NULL,
                    category varchar(255) NOT NULL,
                    ia_type varchar(255) NOT NULL,
                    class varchar(255) NOT NULL,
                    mac varchar(17) NOT NULL,
                    duid varchar(255) NOT NULL,
                    last_update bigint NOT NULL,
                    preferred_until bigint NOT NULL,
                    valid_until bigint NOT NULL,
                    iaid varchar(8) DEFAULT NULL,
                    last_message int(11) NOT NULL DEFAULT 0,
                    PRIMARY KEY (address)
                    );
                    '''
GENERIC_SCHEMA['macs_llips'] = '''
                        CREATE TABLE macs_llips (
                        mac varchar(17) NOT NULL,
                        link_local_ip varchar(39) NOT NULL,
                        last_update bigint NOT NULL,
                        PRIMARY KEY (mac)
                        );
                        '''
GENERIC_SCHEMA['prefixes'] = '''
                    CREATE TABLE prefixes (
                    prefix varchar(32) NOT NULL,
                    length tinyint(4) NOT NULL,
                    active tinyint(4) NOT NULL,
                    preferred_lifetime int(11) NOT NULL,
                    valid_lifetime int(11) NOT NULL,
                    hostname varchar(255) NOT NULL,
                    type varchar(255) NOT NULL,
                    category varchar(255) NOT NULL,
                    class varchar(255) NOT NULL,
                    mac varchar(17) NOT NULL,
                    duid varchar(255) NOT NULL,
                    last_update bigint NOT NULL,
                    preferred_until bigint NOT NULL,
                    valid_until bigint NOT NULL,
                    iaid varchar(8) DEFAULT NULL,
                    last_message int(11) NOT NULL DEFAULT 0,
                    PRIMARY KEY (prefix)
                    );
                    '''
GENERIC_SCHEMA['routes'] = '''
                    CREATE TABLE routes (
                    prefix varchar(32) NOT NULL,
                    length tinyint(4) NOT NULL,
                    router varchar(32) NOT NULL,
                    last_update bigint NOT NULL,
                    PRIMARY KEY (prefix)
                    );
                    '''

# Postgresql has some differences and so its own schemas
POSTGRESQL_SCHEMA = {}
POSTGRESQL_SCHEMA['meta'] = '''
                        CREATE TABLE meta (
                        item_key varchar(255) NOT NULL,
                        item_value varchar(255) NOT NULL,
                        PRIMARY KEY (item_key)
                        );
                        
                        '''
POSTGRESQL_SCHEMA['leases'] = '''
                            CREATE TABLE leases (
                            address varchar(32) NOT NULL,
                            active smallint NOT NULL,
                            preferred_lifetime int NOT NULL,
                            valid_lifetime int NOT NULL,
                            hostname varchar(255) NOT NULL,
                            type varchar(255) NOT NULL,
                            category varchar(255) NOT NULL,
                            ia_type varchar(255) NOT NULL,
                            class varchar(255) NOT NULL,
                            mac varchar(17) NOT NULL,
                            duid varchar(255) NOT NULL,
                            last_update bigint NOT NULL,
                            preferred_until bigint NOT NULL,
                            valid_until bigint NOT NULL,
                            iaid varchar(8) DEFAULT NULL,
                            last_message int NOT NULL DEFAULT 0,
                            PRIMARY KEY (address)
                            );
                            '''
POSTGRESQL_SCHEMA['macs_llips'] = '''
                                CREATE TABLE macs_llips (
                                mac varchar(17) NOT NULL,
                                link_local_ip varchar(39) NOT NULL,
                                last_update bigint NOT NULL,
                                PRIMARY KEY (mac)
                                );
                                '''
POSTGRESQL_SCHEMA['prefixes'] = '''
                            CREATE TABLE prefixes (
                            prefix varchar(32) NOT NULL,
                            length smallint NOT NULL,
                            active smallint NOT NULL,
                            preferred_lifetime int NOT NULL,
                            valid_lifetime int NOT NULL,
                            hostname varchar(255) NOT NULL,
                            type varchar(255) NOT NULL,
                            category varchar(255) NOT NULL,
                            class varchar(255) NOT NULL,
                            mac varchar(17) NOT NULL,
                            duid varchar(255) NOT NULL,
                            last_update bigint NOT NULL,
                            preferred_until bigint NOT NULL,
                            valid_until bigint NOT NULL,
                            iaid varchar(8) DEFAULT NULL,
                            last_message int NOT NULL DEFAULT 0,
                            PRIMARY KEY (prefix)
                            );
                            '''
POSTGRESQL_SCHEMA['routes'] = '''
                            CREATE TABLE routes (
                            prefix varchar(32) NOT NULL,
                            length smallint NOT NULL,
                            router varchar(32) NOT NULL,
                            last_update bigint NOT NULL,
                            PRIMARY KEY (prefix)
                            );
                            '''