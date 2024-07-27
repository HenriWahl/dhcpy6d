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
import traceback

from ..config import cfg
from ..globals import collected_macs
from ..helpers import (decompress_ip6,
                       error_exit,
                       listify_option,
                       NeighborCacheRecord,
                       convert_prefix_inline)
from .schemas import (legacy_adjustments,
                      MYSQL_SQLITE)


class ClientConfig:
    """
        static client settings object to be stuffed into Hosts dict of Textfile store
    """
    def __init__(self, hostname='', client_class='default', duid='', address=None, prefix=None, mac=None, host_id='',
                 prefix_route_link_local=False):
        self.HOSTNAME = hostname
        # MACs
        if type(mac) == list:
            self.MAC = mac
        else:
            self.MAC = listify_option(mac)
        # fixed addresses
        if address:
            self.ADDRESS = list()
            if type(address) == list:
                addresses = address
            else:
                addresses = listify_option(address)
            for a in addresses:
                self.ADDRESS.append(decompress_ip6(a))
        else:
            self.ADDRESS = None

        # fixed prefix
        if prefix:
            self.PREFIX = list()
            if type(prefix) == list:
                prefixes = prefix
            else:
                prefixes = listify_option(prefix)
            for p in prefixes:
                self.PREFIX.append(convert_prefix_inline(p))
        else:
            self.PREFIX = None

        self.CLASS = client_class
        self.ID = host_id
        self.DUID = duid
        self.PREFIX_ROUTE_LINK_LOCAL = prefix_route_link_local


class ClientConfigDicts:
    """
        class for storing client config snippet from DB - used in SQLite and MySQL Storage
    """

    def __init__(self):
        self.hosts = {}
        self.index_mac = {}
        self.index_duid = {}


class Store:
    """
    abstract class to present MySQL or SQLite or Postgresql
    """
    # put SQL schemas here to be in reach of all storage types
    SCHEMAS = MYSQL_SQLITE

    # query to get tables - different in every SQL storage
    # if no tables exist they will be created by create_tables()
    QUERY_TABLES = ''

    # increasing number of SQL schema versions for storage of volatile data
    VOLATILE_SCHEMA_VERSION = 3

    # supported versions of client config database schemas
    CONFIG_SCHEMA_VERSIONS = [1, 2]
    # default host config fields in database, may be extended at least by version 2
    config_fields = ['hostname', 'mac', 'duid', 'class', 'address', 'prefix', 'id']

    # link to used database module
    db_module = None

    # flag for config database prefix support
    config_prefix_support = False

    def __init__(self, query_queue, answer_queue):
        self.query_queue = query_queue
        self.answer_queue = answer_queue
        # table names used for database storage - MySQL additionally needs the database name
        self.table_leases = 'leases'
        self.table_prefixes = 'prefixes'
        self.table_macs_llips = 'macs_llips'
        self.table_hosts = 'hosts'
        self.table_routes = 'routes'
        # flag to check if connection is OK
        self.connected = False
        # storage of query answers
        self.answers = {}
        # schema version of client config entries
        self.config_schema_version = 1

    def query(self, query):
        """
        put queries received into query queue and return the answers from answer queue
        """
        if query in self.answers:
            answer = self.answers.pop(query)
        else:
            answer = None
            while answer is None:
                self.query_queue.put(query)
                self.answers.update(self.answer_queue.get())
                # just make sure the right answer comes back
                if query in self.answers:
                    answer = self.answers.pop(query)
        return answer

    def clean_query_answer(method):
        """
        decorate repeatedly but not everywhere used cleaning of query answer
        """

        def decoration_function(self, *args, **kwargs):
            # run decorated method
            answer = method(self, *args, **kwargs)
            # clean answer
            # SQLite returns list, MySQL tuple - in case someone wonders here...
            if not (answer == [] or answer == () or answer is None):
                return answer[0][0]
            else:
                return None

        return decoration_function

    @clean_query_answer
    def get_db_version(self):
        """
        return stored version if dhcpy6d DB

        """
        try:
            # will be cleaned by decorator so default answer value is a little bit unintuitive
            answer = [['0']]
            if 'meta' in self.get_tables():
                answer = self.query("SELECT item_value FROM meta WHERE item_key = 'version'")
            return answer
        except:
            # no table 'meta' and no key 'version'
            return answer

    def get_tables(self):
        """
        return tables - no turntables
        """
        tables = []
        # every DB type needs another query for tables
        query = self.QUERY_TABLES
        answer = self.query(query)
        if len(answer) > 0:
            tables = [x[0] for x in answer]
        return tables

    def create_tables(self):
        """
        create tables in different storage types - information about schemas comes from schemas.py
        """
        for table in self.SCHEMAS:
            query = self.SCHEMAS[table]
            self.cursor.execute(query)
        # set initial version
        self.cursor.execute(f"INSERT INTO meta (item_key, item_value) VALUES ('version', '{self.VOLATILE_SCHEMA_VERSION}')")

    def check_storage(self):
        """
        check if all databases/storage is ready and up to date
        """
        tables = self.get_tables()
        # if there are no tables they have to be created
        if len(tables) == 0:
            self.create_tables()
        # otherwise they migth need just some updates
        else:
            legacy_adjustments(self)

    def check_config_prefixes_support(self):
        """
        check if client config database contains prefixes - if not just do not ask for prefixes in the future
        """
        # has to be checked only for databases
        if cfg.STORE_CONFIG and cfg.STORE_CONFIG != 'file':
            # first check if database has config information at all
            try:
                self.cursor.execute(f"SELECT hostname, mac, duid, class, address, id FROM {self.table_hosts} LIMIT 1")
            except Exception as error:
                error_exit(f"Config database has problem: {error.args[-1]}")
            # if config information exists check if it also has prefixes
            try:
                self.cursor.execute(f"SELECT hostname, mac, duid, class, address, prefix, id FROM {self.table_hosts} LIMIT 1")
            except:
                return False
            # when query was ok prefix support exists
            self.config_prefix_support = True
            return True

    def store(self, transaction, now):
        """
        store lease in lease DB
        """
        # only if client exists
        if transaction.client:
            for a in transaction.client.addresses:
                if a.ADDRESS is not None:
                    query = f"SELECT address FROM {self.table_leases} WHERE address = '{a.ADDRESS}'"
                    answer = self.query(query)
                    if answer is not None:
                        # if address is not leased yet add it
                        if len(answer) == 0:
                            query = f"INSERT INTO {self.table_leases} (address, active, last_message, " \
                                    f"preferred_lifetime, valid_lifetime, hostname, type, category, ia_type, " \
                                    f"class, mac, duid, iaid, last_update, preferred_until, valid_until) " \
                                    f"VALUES ('{a.ADDRESS}', " \
                                    f"'1', " \
                                    f"'{transaction.last_message_received_type}', " \
                                    f"'{a.PREFERRED_LIFETIME}', " \
                                    f"'{a.VALID_LIFETIME}', " \
                                    f"'{transaction.client.hostname}', " \
                                    f"'{a.TYPE}', " \
                                    f"'{a.CATEGORY}', " \
                                    f"'{a.IA_TYPE}', " \
                                    f"'{transaction.client.client_class}', " \
                                    f"'{transaction.mac}', " \
                                    f"'{transaction.duid}', " \
                                    f"'{transaction.iaid}', " \
                                    f"'{now}', " \
                                    f"'{now + int(a.PREFERRED_LIFETIME)}', " \
                                    f"'{now + int(a.VALID_LIFETIME)}')"
                            answer = self.query(query)
                            # for unknown reasons sometime a lease shall be inserted which already exists
                            # in this case go further (aka continue) and do an update instead of an insert
                            if answer == 'INSERT_ERROR':
                                print('IntegrityError:', query)
                            else:
                                # jump to next item of loop
                                continue
                        # otherwise update it if not a random address
                        if a.CATEGORY != 'random':
                            query = f"UPDATE {self.table_leases} " \
                                    f"SET active = 1, " \
                                    f"last_message = {transaction.last_message_received_type}, " \
                                    f"preferred_lifetime = '{a.PREFERRED_LIFETIME}', " \
                                    f"valid_lifetime = '{a.VALID_LIFETIME}', " \
                                    f"hostname = '{transaction.client.hostname}', " \
                                    f"type = '{a.TYPE}', " \
                                    f"category = '{a.CATEGORY}', " \
                                    f"ia_type = '{a.IA_TYPE}', " \
                                    f"class = '{transaction.client.client_class}', " \
                                    f"mac = '{transaction.mac}', " \
                                    f"duid = '{transaction.duid}', " \
                                    f"iaid = '{transaction.iaid}', " \
                                    f"last_update = '{now}', " \
                                    f"preferred_until = '{now + int(a.PREFERRED_LIFETIME)}', " \
                                    f"valid_until = '{now + int(a.VALID_LIFETIME)}' " \
                                    f"WHERE address = '{a.ADDRESS}'"
                        else:
                            # set last message type of random address
                            query = f"UPDATE {self.table_leases} " \
                                    f"SET active = 1, " \
                                    f"last_message = {transaction.last_message_received_type} " \
                                    f"WHERE address = '{a.ADDRESS}'"
                        self.query(query)

            for p in transaction.client.prefixes:
                if p.PREFIX is not None:
                    query = f"SELECT prefix FROM {self.table_prefixes} WHERE prefix = '{p.PREFIX}'"
                    answer = self.query(query)
                    if answer is not None:
                        # if prefix is not leased yet add it
                        if len(answer) == 0:
                            query = f"INSERT INTO {self.table_prefixes} (prefix, length, active, last_message, " \
                                    f"preferred_lifetime, valid_lifetime, hostname, type, category, class, mac, duid, " \
                                    f"iaid, last_update, preferred_until, valid_until) " \
                                    f"VALUES ('{p.PREFIX}', " \
                                    f"'{p.LENGTH}', " \
                                    f"1, " \
                                    f"'{transaction.last_message_received_type}', " \
                                    f"'{p.PREFERRED_LIFETIME}', " \
                                    f"'{p.VALID_LIFETIME}', " \
                                    f"'{transaction.client.hostname}', " \
                                    f"'{p.TYPE}', " \
                                    f"'{p.CATEGORY}', " \
                                    f"'{transaction.client.client_class}', " \
                                    f"'{transaction.mac}', " \
                                    f"'{transaction.duid}', " \
                                    f"'{transaction.iaid}', " \
                                    f"'{now}', " \
                                    f"'{now + int(p.PREFERRED_LIFETIME)}', " \
                                    f"'{now + int(p.VALID_LIFETIME)}')"
                            answer = self.query(query)
                            # for unknow reasons sometime a lease shall be inserted which already exists
                            # in this case go further (aka continue) and do an update instead of an insert
                            # doing this here for prefixes is just a precautional measure
                            if answer != 'INSERT_ERROR':
                                continue
                        # otherwise update it if not a random prefix
                        # anyway right now only the categories 'range' and 'id' exist
                        if p.CATEGORY != 'random':
                            query = f"UPDATE {self.table_prefixes} SET active = 1, " \
                                    f"last_message = {transaction.last_message_received_type}, " \
                                    f"preferred_lifetime = '{p.PREFERRED_LIFETIME}', " \
                                    f"valid_lifetime = '{p.VALID_LIFETIME}', " \
                                    f"hostname = '{transaction.client.hostname}', " \
                                    f"type = '{p.TYPE}', " \
                                    f"category = '{p.CATEGORY}', " \
                                    f"class = '{transaction.client.client_class}', " \
                                    f"mac = '{transaction.mac}', " \
                                    f"duid = '{transaction.duid}', " \
                                    f"iaid = '{transaction.iaid}', " \
                                    f"last_update = '{now}', " \
                                    f"preferred_until = '{now + int(p.PREFERRED_LIFETIME)}', " \
                                    f"valid_until = '{now + int(p.VALID_LIFETIME)}' " \
                                    f"WHERE prefix = '{p.PREFIX}'"
                        else:
                            # set last message type of random prefix
                            query = f"UPDATE {self.table_prefixes} " \
                                    f"SET last_message = {transaction.last_message_received_type}, " \
                                    f"active = 1 " \
                                    f"WHERE prefix = '{p.PREFIX}'"
                        self.query(query)
            return True
        # if no client -> False
        return False

    @clean_query_answer
    def store_route(self, prefix, length, router, now):
        """
        store route in database to keep track of routes and be able to delete them later
        """
        query = f"SELECT prefix FROM {self.table_routes} WHERE prefix = '{prefix}'"
        if self.query is not None:
            if len(self.query(query)) == 0:
                query = f"INSERT INTO {self.table_routes} VALUES ('{prefix}', {length}, '{router}', {now})"
                return self.query(query)
            elif len(self.query(query)) == 1:
                query = f"UPDATE {self.table_routes} SET prefix = '{prefix}', length = {length}, " \
                        f"router = '{router}', last_update = {now} WHERE prefix = '{prefix}'"
                return self.query(query)
            return None
        else:
            return None

    @clean_query_answer
    def get_range_lease_for_recycling(self, prefix='', range_from='', range_to='', duid='', mac=''):
        """
        ask DB for last known leases of an already known host to be recycled
        this is most useful for CONFIRM-requests that will get a not-available-answer but get an
        ADVERTISE with the last known-as-good address for a client
        SOLICIT message type is 1
        """
        query = f"SELECT address FROM {self.table_leases} WHERE " \
                f"category = 'range' AND " \
                f"'{prefix + range_from}' <= address AND " \
                f"address <= '{prefix + range_to}' AND " \
                f"duid = '{duid}' AND " \
                f"mac = '{mac}' AND " \
                f"last_message != 1 " \
                f"ORDER BY last_update DESC LIMIT 1"
        return self.query(query)

    @clean_query_answer
    def get_range_prefix_for_recycling(self, prefix='', length='', range_from='', range_to='', duid='', mac=''):
        """
        ask DB for last known prefixes of an already known host to be recycled
        this is most useful for CONFIRM-requests that will get a not-available-answer but get an
        ADVERTISE with the last known-as-good address for a client
        SOLICIT message type is 1
        """
        query = f"SELECT prefix FROM {self.table_prefixes} WHERE " \
                f"category = 'range' AND " \
                f"'{prefix + range_from + ((128 - int(length)) // 4) * '0'}' <= prefix AND " \
                f"prefix <= '{prefix + range_to + ((128 - int(length)) // 4) * '0'}' AND " \
                f"length = '{length}' AND " \
                f"duid = '{duid}' AND " \
                f"mac = '{mac}' AND " \
                f"last_message != 1 " \
                f"ORDER BY last_update DESC LIMIT 1"
        return self.query(query)

    @clean_query_answer
    def get_highest_range_lease(self, prefix='', range_from='', range_to=''):
        """
        ask DB for highest known leases - if necessary range sensitive
        """
        query = f"SELECT address FROM {self.table_leases} WHERE active = 1 AND " \
                f"category = 'range' AND " \
                f"'{prefix + range_from}' <= address and address <= '{prefix + range_to}' ORDER BY address DESC LIMIT 1"
        return self.query(query)

    @clean_query_answer
    def get_highest_range_prefix(self, prefix='', length='', range_from='', range_to=''):
        """
        ask DB for highest known prefix - if necessary range sensitive
        """
        query = f"SELECT prefix FROM {self.table_prefixes} WHERE active = 1 AND " \
                f"category = 'range' AND " \
                f"'{prefix + range_from + ((128 - int(length)) // 4) * '0'}' <= prefix AND " \
                f"prefix <= '{prefix + range_to + ((128 - int(length)) // 4) * '0'}' AND " \
                f"length = '{length}' ORDER BY prefix DESC LIMIT 1"
        return self.query(query)

    @clean_query_answer
    def get_oldest_inactive_range_lease(self, prefix='', range_from='', range_to=''):
        """
        ask DB for oldest known inactive lease to minimize chance of collisions
        ordered by valid_until to get leases that are free as long as possible
        """
        query = f"SELECT address FROM {self.table_leases} WHERE active = 0 AND " \
                f"category = 'range' AND " \
                f"'{prefix + range_from}' <= address AND " \
                f"address <= '{prefix + range_to}' ORDER BY valid_until ASC LIMIT 1"
        return self.query(query)

    @clean_query_answer
    def get_oldest_inactive_range_prefix(self, prefix='', length='', range_from='', range_to=''):
        """
        ask DB for oldest known inactive prefix to minimize chance of collisions
        ordered by valid_until to get leases that are free as long as possible
        """
        query = f"SELECT prefix FROM {self.table_prefixes} WHERE active = 0 AND " \
                f"category = 'range' AND " \
                f"'{prefix + range_from + ((128 - int(length)) // 4) * '0'}' <= prefix AND " \
                f"prefix <= '{prefix + range_to + ((128 - int(length)) // 4) * '0'}' AND " \
                f"length = '{length}' " \
                f"ORDER BY valid_until ASC LIMIT 1"
        return self.query(query)

    def get_host_lease(self, address):
        """
        get the hostname, DUID, MAC and IAID to verify a lease to delete its address in the DNS
        """
        query = f"SELECT DISTINCT hostname, duid, mac, iaid FROM {self.table_leases} WHERE address='{address}'"
        answer = self.query(query)
        if answer is not None:
            if len(answer) > 0:
                if len(answer[0]) > 0:
                    return answer[0]
                else:
                    # calling method expects quartet of hostname, duid, mac, iad - get None if nothing there
                    return None, None, None, None
            else:
                return None, None, None, None
        else:
            return None, None, None, None

    def get_active_prefixes(self):
        """
        get used prefixes to be able to reinstall their routes
        """
        # query = "SELECT {0}.prefix FROM {0} INNER JOIN {1} ON {0}.prefix = {1}.prefix WHERE {0}.active = 1".format(self.table_prefixes, self.table_routes)
        query = f"SELECT {self.table_prefixes}.prefix FROM {self.table_prefixes} INNER JOIN {self.table_routes} ON " \
                f"{self.table_prefixes}.prefix = {self.table_routes}.prefix WHERE {self.table_prefixes}.active = 1"
        answer = self.query(query)
        active_prefixes = list()
        if answer is not None:
            for prefix in answer:
                active_prefixes.append(prefix[0])
        return active_prefixes

    def get_inactive_prefixes(self):
        """
        get unused prefixes to be able to delete their routes
        """
        # query = "SELECT {0}.prefix FROM {0} INNER JOIN {1} ON {0}.prefix = {1}.prefix WHERE {0}.active = 0".format(self.table_prefixes, self.table_routes)
        query = f"SELECT {self.table_prefixes}.prefix FROM {self.table_prefixes} INNER JOIN {self.table_routes} " \
                f"ON {self.table_prefixes}.prefix = {self.table_routes}.prefix WHERE {self.table_prefixes}.active = 0"
        answer = self.query(query)
        inactive_prefixes = list()
        if answer is not None:
            for prefix in answer:
                inactive_prefixes.append(prefix[0])
        return inactive_prefixes

    def get_route(self, prefix):
        """
        get all route parameters plus class for a certain prefix - mostly to delete the route
        """
        # query = "SELECT {0}.length, {0}.router, {1}.class FROM {0} INNER JOIN {1} WHERE {0}.prefix = {1}.prefix AND {1}.prefix = '{2}'".format(self.table_routes, self.table_prefixes, prefix)
        query = f"SELECT {self.table_routes}.length, {self.table_routes}.router, {self.table_prefixes}.class FROM " \
                f"{self.table_routes} INNER JOIN {self.table_prefixes} WHERE {self.table_routes}.prefix = " \
                f"{self.table_prefixes}.prefix AND {self.table_prefixes}.prefix = '{prefix}'"
        answer = self.query(query)
        if answer is not None:
            if len(answer) > 0:
                if len(answer[0]) > 0:
                    return answer[0]
                else:
                    # calling method expects triple of length, router and class - get None if nothing there
                    return None, None, None
            else:
                return None, None, None
        else:
            return None, None, None

    @clean_query_answer
    def release_lease(self, address, now):
        """
        release a lease via setting its active flag to False
        set last_message to 8 because of RELEASE messages having this message id
        """
        query = f"UPDATE {self.table_leases} SET active = 0, last_message = 8, last_update = '{now}' WHERE address = '{address}'"
        self.query(query)

    @clean_query_answer
    def release_prefix(self, prefix, now):
        """
        release a prefix via setting its active flag to False
        set last_message to 8 because of RELEASE messages having this message id
        """
        query = f"UPDATE {self.table_prefixes} SET active = 0, last_message = 8, last_update = '{now}' WHERE prefix = '{prefix}'"
        self.query(query)

    @clean_query_answer
    def check_number_of_leases(self, prefix='', range_from='', range_to=''):
        """
        check how many leases are stored - used to find out if address range has been exceeded
        """
        query = f"SELECT COUNT(address) FROM {self.table_leases} WHERE address LIKE '{prefix}%' AND " \
                f"'{prefix + range_from}' <= address AND address <= '{prefix + range_to}'"
        return self.query(query)

    @clean_query_answer
    def check_number_of_prefixes(self, prefix='', length='', range_from='', range_to=''):
        """
        check how many leases are stored - used to find out if address range has been exceeded
        """
        query = f"SELECT COUNT(prefix) FROM {self.table_prefixes} WHERE prefix LIKE '{prefix}%' AND " \
                f"'{prefix + range_from + ((128 - int(length)) // 4) * '0'}' <= prefix AND " \
                f"prefix <= '{prefix + range_to + ((128 - int(length)) // 4) * '0'}'"
        return self.query(query)

    def check_lease(self, address, transaction):
        """
        check state of a lease for REBIND and RENEW messages
        """
        # attributes to identify host and lease
        if cfg.IGNORE_IAID:
            query = f"SELECT DISTINCT hostname, address, type, category, ia_type, class, preferred_until " \
                    f"FROM {self.table_leases} WHERE active = 1 AND " \
                    f"address = '{address}' AND " \
                    f"mac = '{transaction.mac}' AND " \
                    f"duid = '{transaction.duid}'"
        else:
            query = f"SELECT DISTINCT hostname, address, type, category, ia_type, class, preferred_until " \
                    f"FROM {self.table_leases} WHERE active = 1 AND " \
                    f"address = '{address}' AND " \
                    f"mac = '{transaction.mac}' AND " \
                    f"duid = '{transaction.duid}' AND " \
                    f"iaid = '{transaction.iaid}'"
        return self.query(query)

    def check_prefix(self, prefix, length, transaction):
        """
        check state of a prefix for REBIND and RENEW messages
        """
        # attributes to identify host and lease
        if cfg.IGNORE_IAID:
            query = f"SELECT DISTINCT hostname, prefix, length, type, category, class, preferred_until " \
                    f"FROM {self.table_prefixes} WHERE active = 1 AND " \
                    f"prefix = '{prefix}' AND " \
                    f"length = '{length}' AND " \
                    f"mac = '{transaction.mac}' AND " \
                    f"duid = '{transaction.duid}'"
        else:
            query = f"SELECT DISTINCT hostname, prefix, length, type, category, class, preferred_until " \
                    f"FROM {self.table_prefixes} WHERE active = 1 AND " \
                    f"prefix = '{prefix}' AND " \
                    f"length = '{length}' AND " \
                    f"mac = '{transaction.mac}' AND " \
                    f"duid = '{transaction.duid}' AND " \
                    f"iaid = '{transaction.iaid}'"
        return self.query(query)

    def check_advertised_lease(self, transaction=None, category='', atype=''):
        """
        check if there are already advertised addresses for client
        """
        # attributes to identify host and lease
        if cfg.IGNORE_IAID:
            query = f"SELECT address FROM {self.table_leases} WHERE last_message = 1 AND " \
                    f"active = 1 AND " \
                    f"mac = '{transaction.mac}' AND " \
                    f"duid = '{transaction.duid}' AND " \
                    f"category = '{category}' AND " \
                    f"type = '{atype}'"
        else:
            query = f"SELECT address FROM {self.table_leases} WHERE last_message = 1 AND " \
                    f"active = 1 AND " \
                    f"mac = '{transaction.mac}' AND " \
                    f"duid = '{transaction.duid}' AND " \
                    f"iaid = '{transaction.iaid}' AND " \
                    f"category = '{category}' AND " \
                    f"type = '{atype}'"
        answer = self.query(query)
        if answer is not None:
            if len(answer) == 0:
                return False
            else:
                return answer[0][0]
        else:
            return False

    def check_advertised_prefix(self, transaction, category='', ptype=''):
        """
        check if there is already an advertised prefix for client
        """
        # attributes to identify host and lease
        if cfg.IGNORE_IAID:
            query = f"SELECT prefix, length FROM {self.table_prefixes} WHERE last_message = 1 AND " \
                    f"active = 1 AND " \
                    f"mac = '{transaction.mac}' AND " \
                    f"duid = '{transaction.duid}' AND " \
                    f"category = '{category}' AND " \
                    f"type = '{ptype}'"
        else:
            query = f"SELECT prefix, length FROM {self.table_prefixes} WHERE last_message = 1 AND " \
                    f"active = 1 AND " \
                    f"mac = '{transaction.mac}' AND " \
                    f"duid = '{transaction.duid}' AND " \
                    f"iaid = '{transaction.iaid}' AND " \
                    f"category = '{category}' AND " \
                    f"type = '{ptype}'"
        answer = self.query(query)
        if answer is not None:
            if len(answer) == 0:
                return False
            else:
                return answer[0][0]
        else:
            return False

    def release_free_leases(self, now):
        """
        release all invalid leases via setting their active flag to False
        """
        query = f"UPDATE {self.table_leases} SET active = 0, last_message = 0 WHERE valid_until < '{now}'"
        return self.query(query)

    def release_free_prefixes(self, now):
        """
            release all invalid prefixes via setting their active flag to False
        """
        query = f"UPDATE {self.table_prefixes} SET active = 0, last_message = 0 WHERE valid_until < '{now}'"
        return self.query(query)

    def remove_leases(self, now, category="random"):
        """
        remove all leases of a certain category like random - they will grow the database
        but be of no further use
        """
        query = f"DELETE FROM {self.table_leases} WHERE active = 0 AND " \
                f"category = '{category}' AND valid_until < '{now}'"
        return self.query(query)

    def remove_route(self, prefix):
        """
        remove a route which is not used anymore
        """
        query = f"DELETE FROM {self.table_routes} WHERE prefix = '{prefix}'"
        return self.query(query)

    def unlock_unused_advertised_leases(self, now):
        """
        unlock leases marked as advertised but apparently never been delivered
        let's say a client should have requested its formerly advertised address after 1 minute
        """
        query = f"UPDATE {self.table_leases} SET last_message = 0 WHERE last_message = 1 AND last_update < '{now + 60}'"
        return self.query(query)

    def unlock_unused_advertised_prefixes(self, now):
        """
            unlock prefixes marked as advertised but apparently never been delivered
            let's say a client should have requested its formerly advertised address after 1 minute
        """
        query = f"UPDATE {self.table_prefixes} SET last_message = 0 WHERE last_message = 1 AND " \
                f"last_update < '{now + 60}'"
        return self.query(query)

    def build_config_from_db(self, transaction):
        """
        get client config from db and build the appropriate config objects and indices
        """
        if transaction.client_config_dicts is None:
            # add client config which seems to fit to transaction
            transaction.client_config_dicts = ClientConfigDicts()

            if self.config_prefix_support:
                # 'mac LIKE' is necessary if multiple MACs are stored in config DB
                query = f"SELECT {', '.join(self.config_fields)} FROM {self.table_hosts} WHERE " \
                        f"hostname = '{transaction.hostname}' OR " \
                        f"mac LIKE '%{transaction.mac}%' OR " \
                        f"duid = '{transaction.duid}'"
                answer = self.query(query)

                # read all sections of config file
                # a section here is a host
                # lowering MAC and DUID information in case they where upper in database
                for host in answer:
                    prefix_route_link_local = False
                    # config schema version 2 adds prefix_route_link_local
                    if 'prefix_route_link_local' in self.config_fields:
                        hostname, mac, duid, client_class, address, prefix, host_id, prefix_route_link_local = host
                    else:
                        hostname, mac, duid, client_class, address, prefix, host_id = host

                    # lower some attributes to comply with values from request
                    if mac:
                        mac = listify_option(mac.lower())
                    if duid:
                        duid = duid.lower()
                    if address:
                        address = listify_option(address.lower())
                    if prefix:
                        prefix = listify_option(prefix.lower())

                    transaction.client_config_dicts.hosts[hostname] = ClientConfig(hostname=hostname,
                                                                                   mac=mac,
                                                                                   duid=duid,
                                                                                   client_class=client_class,
                                                                                   address=address,
                                                                                   prefix=prefix,
                                                                                   host_id=host_id,
                                                                                   prefix_route_link_local=prefix_route_link_local)
                    # and put the host objects into index
                    if transaction.client_config_dicts.hosts[hostname].MAC:
                        for m in transaction.client_config_dicts.hosts[hostname].MAC:
                            if m not in transaction.client_config_dicts.index_mac:
                                transaction.client_config_dicts.index_mac[m] = [transaction.client_config_dicts.hosts[hostname]]
                            else:
                                transaction.client_config_dicts.index_mac[m]. \
                                    append(transaction.client_config_dicts.hosts[hostname])

                    # add DUIDs to IndexDUID
                    if transaction.client_config_dicts.hosts[hostname].DUID != '':
                        if transaction.client_config_dicts.hosts[hostname].DUID not in transaction.client_config_dicts.index_duid:
                            transaction.client_config_dicts.index_duid[transaction.client_config_dicts.hosts[hostname].DUID] = \
                                [transaction.client_config_dicts.hosts[hostname]]
                        else:
                            transaction.client_config_dicts.index_duid[transaction.client_config_dicts.hosts[hostname].DUID]. \
                                append(transaction.client_config_dicts.hosts[hostname])

                    # some cleaning
                    del host, mac, duid, address, prefix, client_class, host_id
            else:
                # 'mac LIKE' is necessary if multiple MACs are stored in config DB
                query = f"SELECT hostname, mac, duid, class, address, id FROM {self.table_hosts} WHERE " \
                        f"hostname = '{transaction.hostname}' OR " \
                        f"mac LIKE '%{transaction.mac}%' OR " \
                        f"duid = '{transaction.duid}'"
                answer = self.query(query)

                # read all sections of config file
                # a section here is a host
                # lowering MAC and DUID information in case they where upper in database
                for host in answer:
                    hostname, mac, duid, client_class, address, host_id = host
                    # lower some attributes to comply with values from request
                    if mac:
                        mac = listify_option(mac.lower())
                    if duid:
                        duid = duid.lower()
                    if address:
                        address = listify_option(address.lower())

                    transaction.client_config_dicts.hosts[hostname] = ClientConfig(hostname=hostname,
                                                                                   mac=mac,
                                                                                   duid=duid,
                                                                                   client_class=client_class,
                                                                                   address=address,
                                                                                   host_id=host_id)
                    # and put the host objects into index
                    if transaction.client_config_dicts.hosts[hostname].MAC:
                        for m in transaction.client_config_dicts.hosts[hostname].MAC:
                            if m not in transaction.client_config_dicts.index_mac:
                                transaction.client_config_dicts.index_mac[m] = [transaction.client_config_dicts.hosts[hostname]]
                            else:
                                transaction.client_config_dicts.index_mac[m]. \
                                    append(transaction.client_config_dicts.hosts[hostname])

                    # add DUIDs to IndexDUID
                    if transaction.client_config_dicts.hosts[hostname].DUID != '':
                        if transaction.client_config_dicts.hosts[hostname].DUID not in transaction.client_config_dicts.index_duid:
                            transaction.client_config_dicts.index_duid[transaction.client_config_dicts.hosts[hostname].DUID] = \
                                [transaction.client_config_dicts.hosts[hostname]]
                        else:
                            transaction.client_config_dicts.index_duid[transaction.client_config_dicts.hosts[hostname].DUID]. \
                                append(transaction.client_config_dicts.hosts[hostname])

                    # some cleaning
                    del host, mac, duid, address, client_class, host_id

    def get_client_config_by_mac(self, transaction):
        """
        get host and its information belonging to that mac
        """
        hosts = list()
        mac = transaction.mac

        if mac in transaction.client_config_dicts.index_mac:
            hosts.extend(transaction.client_config_dicts.index_mac[mac])
            return hosts
        else:
            return None

    def get_client_config_by_duid(self, transaction):
        """
            get host and its information belonging to that DUID
        """
        # get client config that most probably seems to fit
        hosts = list()
        duid = transaction.duid

        if duid in transaction.client_config_dicts.index_duid:
            hosts.extend(transaction.client_config_dicts.index_duid[duid])
            return hosts
        else:
            return None

    def get_client_config_by_hostname(self, transaction):
        """
            get host and its information by hostname
        """
        hostname = transaction.hostname
        if hostname in transaction.client_config_dicts.hosts:
            return [transaction.client_config_dicts.hosts[hostname]]
        else:
            return None

    def get_client_config(self, hostname='', client_class='', duid='', address=[], mac=[], host_id=''):
        """
            give back ClientConfig object
        """
        return ClientConfig(hostname=hostname,
                            client_class=client_class,
                            duid=duid,
                            address=address,
                            mac=mac,
                            host_id=host_id)

    def store_mac_llip(self, mac, link_local_ip, now):
        """
            store MAC-link-local-ip-mapping
        """
        query = f"SELECT mac FROM macs_llips WHERE mac='{mac}'"
        db_entry = self.query(query)
        # if known already update timestamp of MAC-link-local-ip-mapping
        if not db_entry or db_entry == []:
            query = f"INSERT INTO macs_llips (mac, link_local_ip, last_update) " \
                    f"VALUES ('{mac}', '{link_local_ip}', '{now}')"
            self.query(query)
        else:
            query = f"UPDATE macs_llips SET link_local_ip = '{link_local_ip}', last_update = '{now}' WHERE mac = '{mac}'"
            self.query(query)

    @clean_query_answer
    def get_dynamic_prefix(self):
        query = "SELECT item_value FROM meta WHERE item_key = 'dynamic_prefix'"
        return self.query(query)

    def store_dynamic_prefix(self, prefix):
        """
            store dynamic prefix to be persistent after restart of dhcpy6d
        """
        query = "SELECT item_value FROM meta WHERE item_key = 'dynamic_prefix'"
        db_entry = self.query(query)

        # if already existing just update dynamic prefix
        if not db_entry or db_entry == []:
            query = f"INSERT INTO meta (item_key, item_value) VALUES ('dynamic_prefix', '{prefix}')"
            self.query(query)
        else:
            query = f"UPDATE meta SET item_value = '{prefix}' WHERE item_key = 'dynamic_prefix'"
            self.query(query)

    def collect_macs_from_db(self):
        """
            collect all known MACs and link local addresses from database at startup
            to reduce attempts to read neighbor cache
        """
        query = f'SELECT link_local_ip, mac, last_update FROM {self.table_macs_llips}'
        answer = self.query(query)
        if answer:
            for m in answer:
                try:
                    # m[0] is LLIP, m[1] is the matching MAC
                    # interface is ignored
                    collected_macs[m[0]] = NeighborCacheRecord(llip=m[0], mac=m[1], now=m[2])
                except Exception as err:
                    print(err)
                    traceback.print_exc(file=sys.stdout)
                    sys.stdout.flush()
                    return None

    def set_client_config_schema_version(self, version):
        """
        set client schema version, most probably from settings
        """
        if version not in self.CONFIG_SCHEMA_VERSIONS:
            raise Exception(f'Unsupported client config schema version {version}.')
        self.config_schema_version = version
        # extend version 1 fields by version 2
        if self.config_schema_version >= 2:
            self.config_fields += ['prefix_route_link_local']

    def db_query(self, query):
        """
            no not execute query on DB - dummy
        """
        # return empty tuple as dummy
        return ()


class DB(Store):
    """
        MySQL and PostgreSQL database interface
        for robustness http://stackoverflow.com/questions/207981/how-to-enable-mysql-client-auto-re-connect-with-mysqldb
    """
    connection = False
    cursor = False

    def __init__(self, query_queue, answer_queue):
        Store.__init__(self, query_queue, answer_queue)
        self.connection = None
        try:
            self.db_connect()
        except Exception as err:
            print(err)

    def db_connect(self):
        """
        Connect to database server according to database type
        """
        pass
