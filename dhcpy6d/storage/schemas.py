# DHCPy6d DHCPv6 Daemon
#
# Copyright (C) 2009-2024 Henri Wahl <henri@dhcpy6d.de>
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

import sys

from ..config import cfg

# put SQL schemas here to be in reach of all storage types
# generic mostly usable for SQLite and MySQL/MariaDB
MYSQL_SQLITE = {}
MYSQL_SQLITE['meta'] = '''
                    CREATE TABLE meta (
                    item_key varchar(255) NOT NULL,
                    item_value varchar(255) NOT NULL,
                    PRIMARY KEY (item_key)
                    );
                    '''
MYSQL_SQLITE['leases'] = '''
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
MYSQL_SQLITE['macs_llips'] = '''
                        CREATE TABLE macs_llips (
                        mac varchar(17) NOT NULL,
                        link_local_ip varchar(39) NOT NULL,
                        last_update bigint NOT NULL,
                        PRIMARY KEY (mac)
                        );
                        '''
MYSQL_SQLITE['prefixes'] = '''
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
MYSQL_SQLITE['routes'] = '''
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


# formerly part of store.py but might fit better here
def legacy_adjustments(db):
    """
    adjust some existing data to work with newer versions of dhcpy6d
    """
    try:
        if db.query('SELECT last_message FROM leases LIMIT 1') is None:
            # row 'last_message' in schemas 'leases' does not exist yet, comes with version 0.1.6
            db.query('ALTER TABLE leases ADD last_message INT NOT NULL DEFAULT 0')
            print("Adding row 'last_message' to table 'leases' in volatile storage succeeded.")
    except:
        print("\n'ALTER TABLE leases ADD last_message INT NOT NULL DEFAULT 0' on volatile database failed.")
        print('Please apply manually or grant necessary permissions.\n')
        sys.exit(1)

    # after 0.4.3 with working PostgreSQL support the timestamps have to be stores in epoch seconds, not datetime
    # also after 0.4.3 there will be a third table containing meta information - for a first start it should contain
    # a database version number
    try:
        try:
            # only newer databases contain a version number - real ones starting with 1
            # non-existing version is False
            db_version = db.get_db_version()
            if db_version is None or int(db_version) == 0:
                db_operations = []
                # only create meta table if it does not exist yet
                if not 'meta' in db.get_tables():
                    db_operations.append('CREATE TABLE meta (item_key varchar(255) NOT NULL,\
                                  item_value varchar(255) NOT NULL, PRIMARY KEY (item_key))')
                # add version of database scheme
                db_operations.append("INSERT INTO meta (item_key, item_value) VALUES ('version', '1')")
                for db_operation in db_operations:
                    db.query(db_operation)
                    print(f"{db_operation} in volatile storage succeded.")
        except Exception as err:
            print(f"\n{db_operation} on volatile database failed.")
            print('Please apply manually or grant necessary permissions.\n')
            sys.exit(1)
    except Exception as err:
        print('\nSomething went wrong when retrieving version from database.\n')
        sys.exit(1)

    # find out if timestamps still are in datetime format - applies only to sqlite and mysql anyway
    if cfg.STORE_VOLATILE in ['sqlite', 'mysql']:
        db_datetime_test = db.query('SELECT last_update FROM leases LIMIT 1')
        if len(db_datetime_test) > 0:
            import datetime

            # flag to find out which update has to be done
            update_type = False

            # MySQL
            if type(db_datetime_test[0][0]) is datetime.datetime:
                update_type = 'mysql'

            # SQLite
            if type(db_datetime_test[0][0]) is str:
                if ' ' in db_datetime_test[0][0]:
                    update_type = 'sqlite'

            if update_type:
                # add new columns with suffix *_new
                db_tables = {'leases': ['last_update', 'preferred_until', 'valid_until'],
                             'macs_llips': ['last_update']}

                if update_type == 'mysql':
                    for table in db_tables:
                        for column in db_tables[table]:
                            db.query(f'ALTER TABLE {table} ADD COLUMN {column}_new bigint NOT NULL')
                            print(f'ALTER TABLE {table} ADD COLUMN {column}_new bigint NOT NULL succeeded')
                    # get old timestamps
                    timestamps_old = db.query(
                        'SELECT address, last_update, preferred_until, valid_until FROM leases')
                    for timestamp_old in timestamps_old:
                        address, last_update, preferred_until, valid_until = timestamp_old
                        # convert SQLite datetime values from unicode to Python datetime
                        if update_type == 'sqlite':
                            last_update = datetime.datetime.strptime(last_update, '%Y-%m-%d %H:%M:%S.%f')
                            preferred_until = datetime.datetime.strptime(preferred_until, '%Y-%m-%d %H:%M:%S.%f')
                            valid_until = datetime.datetime.strptime(valid_until, '%Y-%m-%d %H:%M:%S.%f')

                        last_update_new = last_update.strftime('%s')
                        preferred_until_new = preferred_until.strftime('%s')
                        valid_until_new = valid_until.strftime('%s')
                        db.query(f"UPDATE leases SET last_update_new = {last_update_new}, "
                                 f"preferred_until_new = {preferred_until_new}, "
                                 f"valid_until_new = {valid_until_new} "
                                 f"WHERE address = '{address}'")
                    print('Converting timestamps of leases succeeded')
                    timestamps_old = db.query('SELECT mac, last_update FROM macs_llips')
                    for timestamp_old in timestamps_old:
                        mac, last_update = timestamp_old
                        last_update_new = last_update.strftime('%s')
                        db.query(f"UPDATE macs_llips SET last_update_new = {last_update_new} WHERE mac = '{mac}'")
                    print('Converting timestamps of macs_llips succeeded')
                    for table in db_tables:
                        for column in db_tables[table]:
                            db.query(f'ALTER TABLE {table} DROP COLUMN {column}')
                            db.query(f'ALTER TABLE {table} CHANGE COLUMN {column}_new {column} BIGINT NOT NULL')
                            print(f'Moving column {column} of table {table} succeeded')

                if update_type == 'sqlite':
                    for table in db_tables:
                        db.query(f'ALTER TABLE {table} RENAME TO {table}_old')

                    db.query('CREATE TABLE leases AS SELECT address,active,last_message,preferred_lifetime,'
                             'valid_lifetime,hostname,type,category,ia_type,'
                             'class,mac,duid,iaid '
                             'FROM leases_old')

                    db.query('CREATE TABLE macs_llips AS SELECT mac,link_local_ip FROM macs_llips_old')

                    # add timestamp columns in bigint format instead of datetime
                    for table in db_tables:
                        for column in db_tables[table]:
                            db.query(f'ALTER TABLE {table} ADD COLUMN {column} bigint')

                    # get old timestamps
                    timestamps_old = db.query(
                        'SELECT address, last_update, preferred_until, valid_until FROM leases_old')
                    for timestamp_old in timestamps_old:
                        address, last_update, preferred_until, valid_until = timestamp_old
                        # convert SQLite datetime values from unicode to Python datetime
                        if update_type == 'sqlite':
                            last_update = datetime.datetime.strptime(last_update, '%Y-%m-%d %H:%M:%S.%f')
                            preferred_until = datetime.datetime.strptime(preferred_until, '%Y-%m-%d %H:%M:%S.%f')
                            valid_until = datetime.datetime.strptime(valid_until, '%Y-%m-%d %H:%M:%S.%f')

                        last_update_new = last_update.strftime('%s')
                        preferred_until_new = preferred_until.strftime('%s')
                        valid_until_new = valid_until.strftime('%s')
                        db.query(f"UPDATE leases SET last_update = {last_update_new}, "
                                 f"preferred_until = {preferred_until_new}, "
                                 f"valid_until = {valid_until_new} "
                                 f"WHERE address = '{address}'")
                    print('Converting timestamps of leases succeeded')
                    timestamps_old = db.query('SELECT mac, last_update FROM macs_llips_old')
                    for timestamp_old in timestamps_old:
                        mac, last_update = timestamp_old
                        last_update_new = last_update.strftime('%s')
                        db.query(f"UPDATE macs_llips SET last_update = {last_update_new} WHERE mac = '{mac}'")
                    print('Converting timestamps of macs_llips succeeded')

    # Extend volatile database to handle prefixes - comes with database version 2
    if int(db.get_db_version()) < 2:
        if not 'prefixes' in db.get_tables():
            if cfg.STORE_VOLATILE in ['sqlite', 'mysql']:
                db.query('CREATE TABLE prefixes (\
                              prefix varchar(32) NOT NULL,\
                              length tinyint(4) NOT NULL,\
                              active tinyint(4) NOT NULL,\
                              preferred_lifetime int(11) NOT NULL,\
                              valid_lifetime int(11) NOT NULL,\
                              hostname varchar(255) NOT NULL,\
                              type varchar(255) NOT NULL,\
                              category varchar(255) NOT NULL,\
                              class varchar(255) NOT NULL,\
                              mac varchar(17) NOT NULL,\
                              duid varchar(255) NOT NULL,\
                              last_update bigint NOT NULL,\
                              preferred_until bigint NOT NULL,\
                              valid_until bigint NOT NULL,\
                              iaid varchar(8) DEFAULT NULL,\
                              last_message int(11) NOT NULL DEFAULT 0,\
                              PRIMARY KEY (prefix)\
                            )')

            elif cfg.STORE_VOLATILE == 'postgresql':
                db.query('CREATE TABLE prefixes (\
                              prefix varchar(32) NOT NULL,\
                              length smallint NOT NULL,\
                              active smallint NOT NULL,\
                              preferred_lifetime int NOT NULL,\
                              valid_lifetime int NOT NULL,\
                              hostname varchar(255) NOT NULL,\
                              type varchar(255) NOT NULL,\
                              category varchar(255) NOT NULL,\
                              class varchar(255) NOT NULL,\
                              mac varchar(17) NOT NULL,\
                              duid varchar(255) NOT NULL,\
                              last_update bigint NOT NULL,\
                              preferred_until bigint NOT NULL,\
                              valid_until bigint NOT NULL,\
                              iaid varchar(8) DEFAULT NULL,\
                              last_message int NOT NULL DEFAULT 0,\
                              PRIMARY KEY (prefix)\
                            )')

        # increase version to 2
        db.query("UPDATE meta SET item_value='2' WHERE item_key='version'")

        # All OK
        print("Table 'prefixes' is OK")

    # Extend volatile database to handle routes - comes with database version 3
    if int(db.get_db_version()) < 3:
        if not 'prefixes' in db.get_tables():
            if cfg.STORE_VOLATILE in ['sqlite', 'mysql']:
                db.query('CREATE TABLE routes (\
                              prefix varchar(32) NOT NULL,\
                              length tinyint(4) NOT NULL,\
                              router varchar(32) NOT NULL,\
                              last_update bigint NOT NULL,\
                              PRIMARY KEY (prefix)\
                            )')

            elif cfg.STORE_VOLATILE == 'postgresql':
                db.query('CREATE TABLE routes (\
                              prefix varchar(32) NOT NULL,\
                              length smallint NOT NULL,\
                              router varchar(32) NOT NULL,\
                              last_update bigint NOT NULL,\
                              PRIMARY KEY (prefix)\
                            )')

        # increase version to 3
        db.query("UPDATE meta SET item_value='3' WHERE item_key='version'")

        # All OK
        print("Table 'routes' is OK")
