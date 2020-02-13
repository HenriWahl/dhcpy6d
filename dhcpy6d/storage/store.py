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

import sys
import traceback

from ..config import cfg
from ..globals import collected_macs
from ..helpers import (decompress_ip6,
                       error_exit,
                       listify_option,
                       NeighborCacheRecord)


class ClientConfig:
    """
        static client settings object to be stuffed into Hosts dict of Textfile store
    """
    def __init__(self, hostname='', client_class='default', duid='', address=None, mac=None, host_id=''):
        self.HOSTNAME = hostname
        # MACs
        self.MAC = mac
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
        self.CLASS = client_class
        self.ID = host_id
        self.DUID = duid


class ClientConfigDB:
    """
        class for storing client config snippet from DB - used in SQLite and MySQL Storage
    """
    def __init__(self):
        self.hosts = {}
        self.index_mac = {}
        self.index_duid = {}


class Store:
    """
    abstract class to present MySQL or SQLlite
    """
    # def __init__(self, cfg, query_queue, answer_queue, transactions, collected_macs):
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
        self.results = {}

    def query(self, query):
        """
        put queries received into query queue and return the answers from answer queue
        """
        if query in list(self.results.keys()):
            answer = self.results.pop(query)
        else:
            answer = None
            while answer is None:
                self.query_queue.put(query)
                self.results.update(self.answer_queue.get())
                # just make sure the right answer comes back
                if query in list(self.results.keys()):
                    answer = self.results.pop(query)
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
        return self.query("SELECT item_value FROM meta WHERE item_key = 'version'")

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
                            query = f"INSERT INTO {self.table_leases} (address, active, last_message, "\
                                    f"preferred_lifetime, valid_lifetime, hostname, type, category, ia_type, "\
                                    f"class, mac, duid, iaid, last_update, preferred_until, valid_until) "\
                                    f"VALUES ('{a.ADDRESS}', "\
                                    f"'1', "\
                                    f"'{transaction.last_message_received_type}', "\
                                    f"'{a.PREFERRED_LIFETIME}', "\
                                    f"'{a.VALID_LIFETIME}', "\
                                    f"'{transaction.client.hostname}', "\
                                    f"'{a.TYPE}', "\
                                    f"'{a.CATEGORY}', "\
                                    f"'{a.IA_TYPE}', "\
                                    f"'{transaction.client.client_class}', "\
                                    f"'{transaction.mac}', "\
                                    f"'{transaction.duid}', "\
                                    f"'{transaction.iaid}', "\
                                    f"'{now}', "\
                                    f"'{now + int(a.PREFERRED_LIFETIME)}', "\
                                    f"'{now + int(a.VALID_LIFETIME)}')"
                            result = self.query(query)
                            # for unknown reasons sometime a lease shall be inserted which already exists
                            # in this case go further (aka continue) and do an update instead of an insert
                            if result == 'IntegrityError':
                                print('IntegrityError:', query)
                            else:
                                # jump to next item of loop
                                continue
                        # otherwise update it if not a random address
                        if a.CATEGORY != 'random':
                            query = f"UPDATE {self.table_leases} "\
                                    f"SET active = 1, "\
                                    f"last_message = {transaction.last_message_received_type}, "\
                                    f"preferred_lifetime = '{a.PREFERRED_LIFETIME}', "\
                                    f"valid_lifetime = '{a.VALID_LIFETIME}', "\
                                    f"hostname = '{transaction.client.hostname}', "\
                                    f"type = '{a.TYPE}', "\
                                    f"category = '{a.CATEGORY}', "\
                                    f"ia_type = '{a.IA_TYPE}', "\
                                    f"class = '{transaction.client.client_class}', "\
                                    f"mac = '{transaction.mac}', "\
                                    f"duid = '{transaction.duid}', "\
                                    f"iaid = '{transaction.iaid}', "\
                                    f"last_update = '{now}', "\
                                    f"preferred_until = '{now + int(a.PREFERRED_LIFETIME)}', "\
                                    f"valid_until = '{now + int(a.VALID_LIFETIME)}' "\
                                    f"WHERE address = '{a.ADDRESS}'"
                        else:
                            # set last message type of random address
                            query = f"UPDATE {self.table_leases} "\
                                    f"SET active = 1, "\
                                    f"last_message = {transaction.last_message_received_type}, "\
                                    f"WHERE address = '{a.ADDRESS}'"
                        self.query(query)

            for p in transaction.client.prefixes:
                if p.PREFIX is not None:
                    query = f"SELECT prefix FROM {self.table_prefixes} WHERE prefix = '{p.PREFIX}'"
                    answer = self.query(query)
                    if answer is not None:
                        # if prefix is not leased yet add it
                        if len(answer) == 0:
                            query = f"INSERT INTO {self.table_prefixes} (prefix, length, active, last_message, "\
                                    f"preferred_lifetime, valid_lifetime, hostname, type, category, class, mac, duid, "\
                                    f"iaid, last_update, preferred_until, valid_until) "\
                                    f"VALUES ('{p.PREFIX}', "\
                                    f"'{p.LENGTH}', "\
                                    f"1, "\
                                    f"'{transaction.last_message_received_type}', "\
                                    f"'{p.PREFERRED_LIFETIME}, "\
                                    f"'{p.VALID_LIFETIME}', "\
                                    f"'{transaction.client.hostname}', "\
                                    f"'{p.TYPE}', "\
                                    f"'{p.CATEGORY}', "\
                                    f"'{transaction.client.client_class}', "\
                                    f"'{transaction.mac}', "\
                                    f"'{transaction.duid}', "\
                                    f"'{transaction.iaid}', "\
                                    f"'{now}', "\
                                    f"'{now + int(p.PREFERRED_LIFETIME)}', "\
                                    f"'{now + int(p.VALID_LIFETIME)}')"
                            result = self.query(query)
                            # for unknow reasons sometime a lease shall be inserted which already exists
                            # in this case go further (aka continue) and do an update instead of an insert
                            # doing this here for prefixes is just a precautional measure
                            if result != 'IntegrityError':
                                continue
                        # otherwise update it if not a random prefix
                        # anyway right now only th categories 'range' and 'id' exist
                        if p.CATEGORY != 'random':
                            query = f"UPDATE {self.table_prefixes} SET active = 1, "\
                                    f"last_message = {transaction.last_message_received_type}, "\
                                    f"preferred_lifetime = '{p.PREFERRED_LIFETIME}', "\
                                    f"valid_lifetime = '{p.VALID_LIFETIME}', "\
                                    f"hostname = '{transaction.client.hostname}', "\
                                    f"type = '{p.TYPE}', "\
                                    f"category = '{p.CATEGORY}', "\
                                    f"class = '{transaction.client.client_class}', "\
                                    f"mac = '{transaction.mac}', "\
                                    f"duid = '{transaction.duid}', "\
                                    f"iaid = '{transaction.iaid}', "\
                                    f"last_update = '{now}', "\
                                    f"preferred_until = '{now + int(p.PREFERRED_LIFETIME)}', "\
                                    f"valid_until = '{now + int(p.VALID_LIFETIME)}' "\
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
                # query = "UPDATE {0} SET prefix = '{1}', length = {2}, router = '{3}', last_update = {4} WHERE prefix = '{1}'".format(self.table_routes, prefix, length, router, now)
                query = f"UPDATE {self.table_routes} SET prefix = '{prefix}', length = {length}, "\
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
        query = f"SELECT address FROM {self.table_leases} WHERE "\
                f"category = 'range' AND "\
                f"'{prefix+range_from,}' <= address AND "\
                f"address <= '{prefix+range_to}' AND "\
                f"duid = '{duid}' AND "\
                f"mac = '{mac}' AND "\
                f"last_message != 1 "\
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
        query = f"SELECT prefix FROM {self.table_prefixes} WHERE "\
                f"category = 'range' AND "\
                f"'{prefix+range_from+((128-int(length))//4)*'0'}' <= prefix AND "\
                f"prefix <= '{prefix+range_to+((128-int(length))//4)*'0'}' AND "\
                f"length = '{length}' AND "\
                f"duid = '{duid}' AND "\
                f"mac = '{mac}' AND "\
                f"last_message != 1 "\
                f"ORDER BY last_update DESC LIMIT 1"
        return self.query(query)

    @clean_query_answer
    def get_highest_range_lease(self, prefix='', range_from='', range_to=''):
        """
        ask DB for highest known leases - if necessary range sensitive
        """
        query = f"SELECT address FROM {self.table_leases} WHERE active = 1 AND "\
                f"category = 'range' AND "\
                f"'{prefix+range_from}' <= address and address <= '{prefix+range_to}' ORDER BY address DESC LIMIT 1"
        return self.query(query)

    @clean_query_answer
    def get_highest_range_prefix(self, prefix='', length='', range_from='', range_to=''):
        """
        ask DB for highest known prefix - if necessary range sensitive
        """
        query = f"SELECT prefix FROM {self.table_prefixes} WHERE active = 1 AND "\
                f"category = 'range' AND "\
                f"'{prefix+range_from+((128-int(length))//4)*'0'}' <= prefix AND "\
                f"prefix <= '{prefix+range_to+((128-int(length))//4)*'0'}' AND "\
                f"length = '{length}' ORDER BY prefix DESC LIMIT 1"
        return self.query(query)

    @clean_query_answer
    def get_oldest_inactive_range_lease(self, prefix='', range_from='', range_to=''):
        """
        ask DB for oldest known inactive lease to minimize chance of collisions
        ordered by valid_until to get leases that are free as long as possible
        """
        query = f"SELECT address FROM {self.table_leases} WHERE active = 0 AND "\
                f"category = 'range' AND "\
                f"'{prefix+range_from}' <= address AND "\
                f"address <= '{prefix+range_to}' ORDER BY valid_until ASC LIMIT 1"
        return self.query(query)

    @clean_query_answer
    def get_oldest_inactive_range_prefix(self, prefix='', length='', range_from='', range_to=''):
        """
        ask DB for oldest known inactive prefix to minimize chance of collisions
        ordered by valid_until to get leases that are free as long as possible
        """
        query = f"SELECT prefix FROM {self.table_prefixes} WHERE active = 0 AND "\
                f"category = 'range' AND "\
                f"'{prefix+range_from+((128-int(length))//4)*'0'}' <= prefix AND "\
                f"prefix <= '{prefix+range_to+((128-int(length))//4)*'0'}' AND "\
                f"length = '{length}' "\
                f"ORDER BY valid_until ASC LIMIT 1"
        return self.query(query)

    def get_host_lease(self, address):
        """
        get the hostname, DUID, MAC and IAID to verify a lease to delete its address in the DNS
        """
        query = f"SELECT DISTINCT hostname, duid, mac, iaid FROM {self.table_leases} WHERE address='{address}'"
        answer = self.query(query)
        if answer is not None:
            if len(answer)>0:
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
        query = f"SELECT {self.table_prefixes}.prefix FROM {self.table_prefixes} INNER JOIN {self.table_routes} ON "\
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
        query = f"SELECT {self.table_prefixes}.prefix FROM {self.table_prefixes} INNER JOIN {self.table_routes} "\
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
        query = f"SELECT {self.table_routes}.length, {self.table_routes}.router, {self.table_prefixes}.class FROM "\
                f"{self.table_routes} INNER JOIN {self.table_prefixes} WHERE {self.table_routes}.prefix = "\
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
        query = f"SELECT COUNT(address) FROM {self.table_leases} WHERE address LIKE '{prefix}%' AND "\
                f"'{prefix+range_from}' <= address AND address <= '{prefix+range_to}'"
        return self.query(query)

    @clean_query_answer
    def check_number_of_prefixes(self, prefix='', length='', range_from='', range_to=''):
        """
        check how many leases are stored - used to find out if address range has been exceeded
        """
        query = f"SELECT COUNT(prefix) FROM {self.table_prefixes} WHERE prefix LIKE '{prefix}%' AND "\
                f"'{prefix+range_from+((128-int(length))//4)*'0'}' <= prefix AND "\
                f"prefix <= '{prefix+range_to+((128-int(length))//4)*'0'}'"
        return self.query(query)

    def check_lease(self, address, transaction):
        """
        check state of a lease for REBIND and RENEW messages
        """
        # attributes to identify host and lease
        if cfg.IGNORE_IAID:
            query = f"SELECT DISTINCT hostname, address, type, category, ia_type, class, preferred_until "\
                    f"FROM {self.table_leases} WHERE active = 1 AND "\
                    f"address = '{address}' AND "\
                    f"mac = '{transaction.mac}' AND "\
                    f"duid = '{transaction.duid}'"
        else:
            query = f"SELECT DISTINCT hostname, address, type, category, ia_type, class, preferred_until "\
                    f"FROM {self.table_leases} WHERE active = 1 AND "\
                    f"address = '{address}' AND "\
                    f"mac = '{transaction.mac}' AND "\
                    f"duid = '{transaction.duid}' AND "\
                    f"iaid = '{transaction.iaid}'"
        return self.query(query)

    def check_prefix(self, prefix, length, transaction):
        """
        check state of a prefix for REBIND and RENEW messages
        """
        # attributes to identify host and lease
        if cfg.IGNORE_IAID:
            query = f"SELECT DISTINCT hostname, prefix, length, type, category, class, preferred_until "\
                    f"FROM {self.table_prefixes} WHERE active = 1 AND "\
                    f"prefix = '{prefix}' AND "\
                    f"length = '{length}' AND "\
                    f"mac = '{transaction.mac}' AND "\
                    f"duid = '{transaction.duid}'"
        else:
            query = f"SELECT DISTINCT hostname, prefix, length, type, category, class, preferred_until "\
                    f"FROM {self.table_prefixes} WHERE active = 1 AND "\
                    f"prefix = '{prefix}' AND "\
                    f"length = '{length}' AND "\
                    f"mac = '{transaction.mac}' AND "\
                    f"duid = '{transaction.duid}' AND "\
                    f"iaid = '{transaction.iaid}'"
        return self.query(query)

    def check_advertised_lease(self, transaction=None, category='', atype=''):
        """
        check if there are already advertised addresses for client
        """
        # attributes to identify host and lease
        if cfg.IGNORE_IAID:
            query = f"SELECT address FROM {self.table_leases} WHERE last_message = 1 AND "\
                    f"active = 1 AND "\
                    f"mac = '{transaction.mac}' AND "\
                    f"duid = '{transaction.duid}' AND "\
                    f"category = '{category}' AND "\
                    f"type = '{atype}'"
        else:
            query = f"SELECT address FROM {self.table_leases} WHERE last_message = 1 AND "\
                    f"active = 1 AND "\
                    f"mac = '{transaction.mac}' AND "\
                    f"duid = '{transaction.duid}' AND "\
                    f"iaid = '{transaction.iaid}' AND "\
                    f"category = '{category}' AND "\
                    f"type = '{atype}'"
        result = self.query(query)
        if result is not None:
            if len(result) == 0:
                return False
            else:
                return result[0][0]
        else:
            return False

    def check_advertised_prefix(self, transaction, category='', ptype=''):
        """
        check if there is already an advertised prefix for client
        """
        # attributes to identify host and lease
        if cfg.IGNORE_IAID:
            query = f"SELECT prefix, length FROM {self.table_prefixes} WHERE last_message = 1 AND "\
                    f"active = 1 AND "\
                    f"mac = '{transaction.mac}' AND "\
                    f"duid = '{transaction.duid}' AND "\
                    f"category = '{category}' AND "\
                    f"type = '{ptype}'"
        else:
            query = f"SELECT prefix, length FROM {self.table_prefixes} WHERE last_message = 1 AND "\
                    f"active = 1 AND "\
                    f"mac = '{transaction.mac}' AND "\
                    f"duid = '{transaction.duid}' AND "\
                    f"iaid = '{transaction.iaid}' AND "\
                    f"category = '{category}' AND "\
                    f"type = '{ptype}'"
        result = self.query(query)
        if result is not None:
            if len(result) == 0:
                return False
            else:
                return result[0][0]
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
        query = f"DELETE FROM {self.table_leases} WHERE active = 0 AND "\
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
        query = f"UPDATE {self.table_prefixes} SET last_message = 0 WHERE last_message = 1 AND "\
                f"last_update < '{now + 60}'"
        return self.query(query)

    def build_config_from_db(self, transaction):
        """
        get client config from db and build the appropriate config objects and indices
        """
        if transaction.client_config_db is None:
            query = f"SELECT hostname, mac, duid, class, address, id FROM {self.table_hosts} WHERE "\
                    f"hostname = '{transaction.hostname}' OR "\
                    f"mac LIKE '%{transaction.mac}%' OR "\
                    f"duid = '{transaction.duid}'"
            answer = self.query(query)

            # add client config which seems to fit to transaction
            transaction.client_config_db = ClientConfigDB()

            # read all sections of config file
            # a section here is a host
            # lowering MAC and DUID information in case they where upper in database
            for host in answer:
                hostname, mac, duid, aclass, address, host_id = host
                # lower some attributes to comply with values from request
                if mac:
                    mac = listify_option(mac.lower())
                if duid:
                    duid = duid.lower()
                if address:
                    address = listify_option(address.lower())

                transaction.client_config_db.hosts[hostname] = ClientConfig(hostname=hostname,
                                                                            mac=mac,
                                                                            duid=duid,
                                                                            client_class=aclass,
                                                                            address=address,
                                                                            host_id=host_id)
                # and put the host objects into index
                if transaction.client_config_db.hosts[hostname].MAC:
                    for m in transaction.client_config_db.hosts[hostname].MAC:
                        if m not in transaction.client_config_db.index_mac:
                            transaction.client_config_db.index_mac[m] = [transaction.client_config_db.hosts[hostname]]
                        else:
                            transaction.client_config_db.index_mac[m].\
                                append(transaction.client_config_db.hosts[hostname])

                # add DUIDs to IndexDUID
                if transaction.client_config_db.hosts[hostname].DUID != '':
                    if transaction.client_config_db.hosts[hostname].DUID not in transaction.client_config_db.index_duid:
                        transaction.client_config_db.index_duid[transaction.client_config_db.hosts[hostname].DUID] = \
                            [transaction.client_config_db.hosts[hostname]]
                    else:
                        transaction.client_config_db.index_duid[transaction.client_config_db.hosts[hostname].DUID].\
                            append(transaction.client_config_db.hosts[hostname])

                # some cleaning
                del host, mac, duid, address, aclass, host_id

    def get_client_config_by_mac(self, transaction):
        """
        get host and its information belonging to that mac
        """
        hosts = list()
        mac = transaction.mac

        if mac in transaction.client_config_db.index_mac:
            hosts.extend(transaction.client_config_db.index_mac[mac])
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

        if duid in transaction.client_config_db.index_duid:
            hosts.extend(transaction.client_config_db.index_duid[duid])
            return hosts
        else:
            return None

    def get_client_config_by_hostname(self, transaction):
        """
            get host and its information by hostname
        """
        hostname = transaction.hostname
        if hostname in transaction.client_config_db.hosts:
            return [transaction.client_config_db.hosts[hostname]]
        else:
            return None

    def get_client_config(self, hostname='', client_class='', duid='', address=[], mac=[], host_id=''):
        """
            give back ClientConfig object
        """
        return ClientConfig(hostname=hostname, client_class=client_class, duid=duid, address=address, mac=mac, host_id=host_id)

    def store_mac_llip(self, mac, link_local_ip, now):
        """
            store MAC-link-local-ip-mapping
        """
        query = f"SELECT mac FROM macs_llips WHERE mac='{mac}'"
        db_entry = self.query(query)
        # if known already update timestamp of MAC-link-local-ip-mapping
        if not db_entry or db_entry == []:
            query = f"INSERT INTO macs_llips (mac, link_local_ip, last_update) "\
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
            query = f"INSERT INTO meta (item_key, item_value) VALUES ('{'dynamic_prefix'}', '{prefix}')"
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

    def db_query(self, query):
        """
            no not execute query on DB - dummy
        """
        # return empty tuple as dummy
        return ()

    def legacy_adjustments(self):
        """
            adjust some existing data to work with newer versions of dhcpy6d
        """
        try:
            if self.query('SELECT last_message FROM leases LIMIT 1') is None:
                # row 'last_message' in tables 'leases' does not exist yet, comes with version 0.1.6
                self.query('ALTER TABLE leases ADD last_message INT NOT NULL DEFAULT 0')
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
                # only newer databases contain a version number - starting with 1
                if self.get_db_version() is None:
                    # add table containing meta information like version of database scheme
                    db_operations = ['CREATE TABLE meta (item_key varchar(255) NOT NULL,\
                                      item_value varchar(255) NOT NULL, PRIMARY KEY (item_key))',
                                     "INSERT INTO meta (item_key, item_value) VALUES ('version', '1')"]
                    for db_operation in db_operations:
                        self.query(db_operation)
                        print(f'{db_operation} in volatile storage succeded.')
            except:
                print(f"\n{db_operation} on volatile database failed.")
                print('Please apply manually or grant necessary permissions.\n')
                sys.exit(1)
        except:
            print('\nSomething went wrong when retrieving version from database.\n')
            sys.exit(1)

        # find out if timestamps still are in datetime format - applies only to sqlite and mysql anyway
        if cfg.STORE_VOLATILE in ['sqlite', 'mysql']:
            db_datetime_test = self.query('SELECT last_update FROM leases LIMIT 1')
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
                                self.query(f'ALTER TABLE {table} ADD COLUMN {column}_new bigint NOT NULL')
                                print(f'ALTER TABLE {table} ADD COLUMN {column}_new bigint NOT NULL succeeded')
                        # get old timestamps
                        timestamps_old = self.query('SELECT address, last_update, preferred_until, valid_until FROM leases')
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
                            # self.query("UPDATE leases SET last_update_new = {0}, "
                            #                                       "preferred_until_new = {1}, "
                            #                                       "valid_until_new = {2} "
                            #                     "WHERE address = '{3}'".format(last_update_new,
                            #                                                    preferred_until_new,
                            #                                                    valid_until_new,
                            #                                                    address))
                            self.query(f"UPDATE leases SET last_update_new = {last_update_new}, "
                                       f"preferred_until_new = {preferred_until_new}, "
                                       f"valid_until_new = {valid_until_new} "
                                       f"WHERE address = '{address}'")
                        print('Converting timestamps of leases succeeded')
                        timestamps_old = self.query('SELECT mac, last_update FROM macs_llips')
                        for timestamp_old in timestamps_old:
                            mac, last_update = timestamp_old
                            last_update_new = last_update.strftime('%s')
                            self.query(f"UPDATE macs_llips SET last_update_new = {last_update_new} WHERE mac = '{mac}'")
                        print('Converting timestamps of macs_llips succeeded')
                        for table in db_tables:
                            for column in db_tables[table]:
                                self.query(f'ALTER TABLE {table} DROP COLUMN {column}')
                                self.query(f'ALTER TABLE {table} CHANGE COLUMN {column}_new {column} BIGINT NOT NULL')
                                print(f'Moving column {column} of table {table} succeeded')

                    if update_type == 'sqlite':
                        for table in db_tables:
                            self.query(f'ALTER TABLE {table} RENAME TO {table}_old')

                        self.query('CREATE TABLE leases AS SELECT address,active,last_message,preferred_lifetime,'
                                   'valid_lifetime,hostname,type,category,ia_type,'
                                   'class,mac,duid,iaid '
                                   'FROM leases_old')

                        self.query('CREATE TABLE macs_llips AS SELECT mac,link_local_ip FROM macs_llips_old')

                        # add timestamp columns in bigint format instead of datetime
                        for table in db_tables:
                            for column in db_tables[table]:
                                self.query(f'ALTER TABLE {table} ADD COLUMN {column} bigint')

                        # get old timestamps
                        timestamps_old = self.query('SELECT address, last_update, preferred_until, valid_until FROM leases_old')
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
                            self.query(f"UPDATE leases SET last_update = {last_update_new}, "
                                       f"preferred_until = {preferred_until_new}, "
                                       f"valid_until = {valid_until_new} "
                                       f"WHERE address = '{address}'")
                        print('Converting timestamps of leases succeeded')
                        timestamps_old = self.query('SELECT mac, last_update FROM macs_llips_old')
                        for timestamp_old in timestamps_old:
                            mac, last_update = timestamp_old
                            last_update_new = last_update.strftime('%s')
                            self.query(f"UPDATE macs_llips SET last_update = {last_update_new} WHERE mac = '{mac}'")
                        print('Converting timestamps of macs_llips succeeded')

        # Extend volatile database to handle prefixes - comes with database version 2
        if int(self.get_db_version()) < 2:
            if cfg.STORE_VOLATILE in ['sqlite', 'mysql']:
                self.query('CREATE TABLE prefixes (\
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
                self.query('CREATE TABLE prefixes (\
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
            self.query("UPDATE meta SET item_value='2' WHERE item_key='version'")

            # All OK
            print("Adding table 'prefixes' succeeded")

        # Extend volatile database to handle routes - comes with database version 3
        if int(self.get_db_version()) < 3:
            if cfg.STORE_VOLATILE in ['sqlite', 'mysql']:
                self.query('CREATE TABLE routes (\
                              prefix varchar(32) NOT NULL,\
                              length tinyint(4) NOT NULL,\
                              router varchar(32) NOT NULL,\
                              last_update bigint NOT NULL,\
                              PRIMARY KEY (prefix)\
                            )')

            elif cfg.STORE_VOLATILE == 'postgresql':
                self.query('CREATE TABLE routes (\
                              prefix varchar(32) NOT NULL,\
                              length smallint NOT NULL,\
                              router varchar(32) NOT NULL,\
                              last_update bigint NOT NULL,\
                              PRIMARY KEY (prefix)\
                            )')

            # increase version to 3
            self.query("UPDATE meta SET item_value='3' WHERE item_key='version'")

            # All OK
            print("Adding table 'routes' succeeded")


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
        if cfg.STORE_CONFIG == 'mysql' or cfg.STORE_VOLATILE == 'mysql':
            try:
                if 'MySQLdb' not in list(sys.modules.keys()):
                    import MySQLdb
            except:
                error_exit('ERROR: Cannot find module MySQLdb. Please install to proceed.')
            try:
                self.connection = sys.modules['MySQLdb'].connect(host=cfg.STORE_DB_HOST,
                                                   db=cfg.STORE_DB_DB,
                                                   user=cfg.STORE_DB_USER,
                                                   passwd=cfg.STORE_DB_PASSWORD)
                self.connection.autocommit(True)
                self.cursor = self.connection.cursor()
                self.connected = True
            except:
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
                self.connected = False

        elif cfg.STORE_CONFIG == 'postgresql' or cfg.STORE_VOLATILE == 'postgresql':
            try:
                if 'psycopg2' not in list(sys.modules.keys()):
                    import psycopg2
            except:
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
                error_exit('ERROR: Cannot find module psycopg2. Please install to proceed.')
            try:
                self.connection = sys.modules['psycopg2'].connect(host=cfg.STORE_DB_HOST,
                                                                  database=cfg.STORE_DB_DB,
                                                                  user=cfg.STORE_DB_USER,
                                                                  passwd=cfg.STORE_DB_PASSWORD)
                self.cursor = self.connection.cursor()
                self.connected = True
            except:
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
                self.connected = False
        return self.connected
