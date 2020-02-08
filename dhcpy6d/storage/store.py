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
from ..constants import CONST
from ..globals import (collected_macs,
                       transactions)
from ..helpers import (decompress_ip6,
                       error_exit,
                       listify_option,
                       NeighborCacheRecord)

class ClientConfig:
    """
        static client settings object to be stuffed into Hosts dict of Textfile store
    """
    def __init__(self, hostname='', aclass='default', duid='', address=None, mac=None, id=''):
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
        self.CLASS = aclass
        self.ID = id
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
        self.table_prefixes = CONST.ADVERTISE.PREFIXES
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
        return (decoration_function)

    @clean_query_answer
    def get_db_version(self):
        """
        """
        return(self.query("SELECT item_value FROM meta WHERE item_key = 'version'"))

    def store(self, transaction, now):
        """
        store lease in lease DB
        """
        # only if client exists
        if transaction.client:
            for a in transaction.client.addresses:
                if not a.ADDRESS is None:
                    query = f"SELECT address FROM {self.table_leases} WHERE address = '{a.ADDRESS}'"
                    answer = self.query(query)
                    if answer != None:
                        # if address is not leased yet add it
                        if len(answer) == 0:
                            query = "INSERT INTO %s (address, active, last_message, preferred_lifetime, valid_lifetime,\
                                     hostname, type, category, ia_type, class, mac, duid, iaid, last_update,\
                                     preferred_until, valid_until) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s',\
                                     '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % \
                                  (self.table_leases,
                                   a.ADDRESS,
                                   1,
                                   transaction.last_message_received_type,
                                   a.PREFERRED_LIFETIME,
                                   a.VALID_LIFETIME,
                                   transaction.client.hostname,
                                   a.TYPE,
                                   a.CATEGORY,
                                   a.IA_TYPE,
                                   transaction.client.client_class,
                                   transaction.mac,
                                   transaction.duid,
                                   transaction.iaid,
                                   now,
                                   now + int(a.PREFERRED_LIFETIME),
                                   now + int(a.VALID_LIFETIME))
                            result = self.query(query)
                            # for unknow reasons sometime a lease shall be inserted which already exists
                            # in this case go further (aka continue) and do an update instead of an insert
                            if result == 'IntegrityError':
                                print('IntegrityError:', query)
                            else:
                                # jump to next item of loop
                                continue
                        # otherwise update it if not a random address
                        if a.CATEGORY != 'random':
                            query = "UPDATE %s SET active = 1, last_message = %s, preferred_lifetime = '%s',\
                                     valid_lifetime = '%s', hostname = '%s', type = '%s', category = '%s',\
                                     ia_type = '%s', class = '%s', mac = '%s', duid = '%s', iaid = '%s',\
                                     last_update = '%s', preferred_until = '%s', valid_until = '%s'\
                                     WHERE address = '%s'" % \
                                  (self.table_leases,
                                   transaction.last_message_received_type,
                                   a.PREFERRED_LIFETIME,
                                   a.VALID_LIFETIME,
                                   transaction.client.hostname,
                                   a.TYPE,
                                   a.CATEGORY,
                                   a.IA_TYPE,
                                   transaction.client.client_class,
                                   transaction.mac,
                                   transaction.duid,
                                   transaction.iaid,
                                   now,
                                   now + int(a.PREFERRED_LIFETIME),
                                   now + int(a.VALID_LIFETIME),
                                   a.ADDRESS)
                            self.query(query)
                        else:
                            # set last message type of random address
                            query = "UPDATE %s SET last_message = %s, active = 1 WHERE address = '%s'" %\
                                     (self.table_leases, transaction.last_message_received_type,
                                      a.ADDRESS)
                            self.query(query)

            for p in transaction.client.prefixes:
                if not p.PREFIX is None:
                    query = f"SELECT prefix FROM {self.table_prefixes} WHERE prefix = '{p.PREFIX}'"
                    answer = self.query(query)
                    if answer != None:
                        # if address is not leased yet add it
                        if len(answer) == 0:
                            query = "INSERT INTO %s (prefix, length, active, last_message, preferred_lifetime, valid_lifetime,\
                                     hostname, type, category, class, mac, duid, iaid, last_update,\
                                     preferred_until, valid_until) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',\
                                     '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % \
                                  (self.table_prefixes,
                                   p.PREFIX,
                                   p.LENGTH,
                                   1,
                                   transaction.last_message_received_type,
                                   p.PREFERRED_LIFETIME,
                                   p.VALID_LIFETIME,
                                   transaction.client.hostname,
                                   p.TYPE,
                                   p.CATEGORY,
                                   transaction.client.client_class,
                                   transaction.mac,
                                   transaction.duid,
                                   transaction.iaid,
                                   now,
                                   now + int(p.PREFERRED_LIFETIME),
                                   now + int(p.VALID_LIFETIME))
                            result = self.query(query)
                            # for unknow reasons sometime a lease shall be inserted which already exists
                            # in this case go further (aka continue) and do an update instead of an insert
                            # doing this here for prefixes is just a precautional measure
                            if result != 'IntegrityError':
                                continue
                        # otherwise update it if not a random address
                        if p.CATEGORY != 'random':
                            query = "UPDATE %s SET active = 1, last_message = %s, preferred_lifetime = '%s',\
                                     valid_lifetime = '%s', hostname = '%s', type = '%s', category = '%s',\
                                     class = '%s', mac = '%s', duid = '%s', iaid = '%s',\
                                     last_update = '%s', preferred_until = '%s', valid_until = '%s'\
                                     WHERE prefix = '%s'" % \
                                  (self.table_prefixes,
                                   transaction.last_message_received_type,
                                   p.PREFERRED_LIFETIME,
                                   p.VALID_LIFETIME,
                                   transaction.client.hostname,
                                   p.TYPE,
                                   p.CATEGORY,
                                   transaction.client.client_class,
                                   transaction.mac,
                                   transaction.duid,
                                   transaction.iaid,
                                   now,
                                   now + int(p.PREFERRED_LIFETIME),
                                   now + int(p.VALID_LIFETIME),
                                   p.PREFIX)
                            self.query(query)
                        else:
                            # set last message type of random address
                            query = "UPDATE %s SET last_message = %s, active = 1 WHERE address = '%s'" %\
                                     (self.table_prefixes, transaction.last_message_received_type,
                                      p.PREFIX)
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
                query = "UPDATE {0} SET prefix = '{1}', length = {2}, router = '{3}', last_update = {4} WHERE prefix = '{1}'".format(self.table_routes, prefix, length, router, now)
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
        query = "SELECT address FROM %s WHERE "\
                "category = 'range' AND "\
                "'%s' <= address AND "\
                "address <= '%s' AND "\
                "duid = '%s' AND "\
                "mac = '%s' AND "\
                "last_message != 1 "\
                "ORDER BY last_update DESC LIMIT 1" %\
                (self.table_leases, prefix+range_from, prefix+range_to, duid, mac)
        return self.query(query)

    @clean_query_answer
    def get_range_prefix_for_recycling(self, prefix='', length='', range_from='', range_to='', duid='', mac=''):
        """
        ask DB for last known prefixes of an already known host to be recycled
        this is most useful for CONFIRM-requests that will get a not-available-answer but get an
        ADVERTISE with the last known-as-good address for a client
        SOLICIT message type is 1
        """
        query = "SELECT prefix FROM %s WHERE "\
                "category = 'range' AND "\
                "'%s' <= prefix AND "\
                "prefix <= '%s' AND "\
                "length = '%s' AND "\
                "duid = '%s' AND "\
                "mac = '%s' AND "\
                "last_message != 1 "\
                "ORDER BY last_update DESC LIMIT 1" %\
                (self.table_prefixes,
                 prefix+range_from+((128-int(length))//4)*'0',
                 prefix+range_to+((128-int(length))//4)*'0',
                 length,
                 duid,
                 mac)
        return self.query(query)

    @clean_query_answer
    def get_highest_range_lease(self, prefix='', range_from='', range_to=''):
        """
        ask DB for highest known leases - if necessary range sensitive
        """
        query = "SELECT address FROM %s WHERE active = 1 AND "\
                "category = 'range' AND "\
                "'%s' <= address and address <= '%s' ORDER BY address DESC LIMIT 1" %\
                (self.table_leases,
                 prefix+range_from,
                 prefix+range_to)
        return self.query(query)

    @clean_query_answer
    def get_highest_range_prefix(self, prefix='', length='', range_from='', range_to=''):
        """
        ask DB for highest known prefix - if necessary range sensitive
        """
        query = "SELECT prefix FROM %s WHERE active = 1 AND "\
                "category = 'range' AND "\
                "'%s' <= prefix AND prefix <= '%s' AND "\
                "length = '%s' ORDER BY prefix DESC LIMIT 1" %\
                (self.table_prefixes,
                    prefix+range_from+((128-int(length))//4)*'0',
                    prefix+range_to+((128-int(length))//4)*'0',
                    length)
        return self.query(query)

    @clean_query_answer
    def get_oldest_inactive_range_lease(self, prefix='', range_from='', range_to=''):
        """
        ask DB for oldest known inactive lease to minimize chance of collisions
        ordered by valid_until to get leases that are free as long as possible
        """
        query = "SELECT address FROM %s WHERE active = 0 AND category = 'range' AND "\
                "'%s' <= address AND address <= '%s' ORDER BY valid_until ASC LIMIT 1" %\
                (self.table_leases,
                 prefix+range_from,
                 prefix+range_to)
        return self.query(query)

    @clean_query_answer
    def get_oldest_inactive_range_prefix(self, prefix='', length='', range_from='', range_to=''):
        """
        ask DB for oldest known inactive prefix to minimize chance of collisions
        ordered by valid_until to get leases that are free as long as possible
        """
        query = "SELECT prefix FROM %s WHERE active = 0 AND " \
                "category = 'range' AND "\
                "'%s' <= prefix AND prefix <= '%s' AND " \
                "length = '%s' "\
                "ORDER BY valid_until ASC LIMIT 1" %\
                (self.table_prefixes,
                 prefix+range_from+((128-int(length))//4)*'0',
                 prefix+range_to+((128-int(length))//4)*'0',
                 length)
        return self.query(query)

    def get_host_lease(self, address):
        """
        get the hostname, DUID, MAC and IAID to verify a lease to delete its address in the DNS
        """
        query = f"SELECT DISTINCT hostname, duid, mac, iaid FROM {self.table_leases} WHERE address='{address}'"
        answer = self.query(query)
        if answer != None:
            if len(answer)>0:
                if len(answer[0]) > 0:
                    return answer[0]
                else:
                    # calling method expects quartet of hostname, duid, mac, iad - get None if nothing there
                    return((None, None, None, None))
            else:
                return((None, None, None, None))
        else:
            return((None, None, None, None))

    def get_active_prefixes(self):
        """
        get used prefixes to be able to reinstall their routes
        """
        query = "SELECT {0}.prefix FROM {0} INNER JOIN {1} ON {0}.prefix = {1}.prefix WHERE {0}.active = 1".format(self.table_prefixes, self.table_routes)
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
        query = "SELECT {0}.prefix FROM {0} INNER JOIN {1} ON {0}.prefix = {1}.prefix WHERE {0}.active = 0".format(self.table_prefixes, self.table_routes)
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
        query = "SELECT {0}.length, {0}.router, {1}.class FROM {0} INNER JOIN {1} WHERE {0}.prefix = {1}.prefix AND {1}.prefix = '{2}'".format(self.table_routes, self.table_prefixes, prefix)
        answer = self.query(query)
        if answer != None:
            if len(answer)>0:
                if len(answer[0]) > 0:
                    return answer[0]
                else:
                    # calling method expects triple of length, router and class - get None if nothing there
                    return((None, None, None))
            else:
                return((None, None, None))
        else:
            return((None, None, None))

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
        query = "SELECT COUNT(address) FROM %s WHERE address LIKE '%s%%' AND "\
                "'%s' <= address AND address <= '%s'" % (self.table_leases,
                                                         prefix,
                                                         prefix+range_from,
                                                         prefix+range_to)
        return self.query(query)

    @clean_query_answer
    def check_number_of_prefixes(self, prefix='', length='', range_from='', range_to=''):
        """
        check how many leases are stored - used to find out if address range has been exceeded
        """
        query = "SELECT COUNT(prefix) FROM %s WHERE prefix LIKE '%s%%' AND "\
                "'%s' <= prefix AND prefix <= '%s'" % (self.table_prefixes,
                                                       prefix,
                                                       prefix+range_from+((128-int(length))//4)*'0',
                                                       prefix+range_to+((128-int(length))//4)*'0')
        return self.query(query)

    def check_lease(self, address, transaction_id):
        """
        check state of a lease for REBIND and RENEW messages
        """
        # attributes to identify host and lease
        if cfg.IGNORE_IAID:
            query = "SELECT DISTINCT hostname, address, type, category, ia_type, class, preferred_until FROM %s WHERE active = 1\
                     AND address = '%s' AND mac = '%s' AND duid = '%s'" % \
                    (self.table_leases,
                     address,
                     transactions[transaction_id].mac,
                     transactions[transaction_id].duid)
        else:
            query = "SELECT DISTINCT hostname, address, type, category, ia_type, class, preferred_until FROM %s WHERE active = 1\
                     AND address = '%s' AND mac = '%s' AND duid = '%s' AND iaid = '%s'" % \
                    (self.table_leases,
                     address,
                     transactions[transaction_id].mac,
                     transactions[transaction_id].duid,
                     transactions[transaction_id].iaid)

        return self.query(query)

    def check_prefix(self, prefix, length, transaction_id):
        """
        check state of a prefix for REBIND and RENEW messages
        """
        # attributes to identify host and lease
        if cfg.IGNORE_IAID:
            query = "SELECT DISTINCT hostname, prefix, length, type, category, class, preferred_until FROM %s WHERE active = 1\
                     AND prefix = '%s' AND length = '%s' AND mac = '%s' AND duid = '%s'" % \
                    (self.table_prefixes,
                     prefix,
                     length,
                     transactions[transaction_id].mac,
                     transactions[transaction_id].duid)
        else:
            query = "SELECT DISTINCT hostname, prefix, length, type, category, class, preferred_until FROM %s WHERE active = 1\
                     AND prefix = '%s' AND length = '%s' AND mac = '%s' AND duid = '%s' AND iaid = '%s'" % \
                    (self.table_prefixes,
                     prefix,
                     length,
                     transactions[transaction_id].mac,
                     transactions[transaction_id].duid,
                     transactions[transaction_id].iaid)
        return self.query(query)

    def check_advertised_lease(self, transaction_id='', category='', atype=''):
        """
        check if there are already advertised addresses for client
        """
        # attributes to identify host and lease
        if cfg.IGNORE_IAID:
            query = "SELECT address FROM %s WHERE last_message = 1\
                     AND active = 1\
                     AND mac = '%s' AND duid = '%s'\
                     AND category = '%s' AND type = '%s'" % \
                    (self.table_leases,
                     transactions[transaction_id].mac,
                     transactions[transaction_id].duid,
                     category,
                     atype)
        else:
            query = "SELECT address FROM %s WHERE last_message = 1\
                     AND active = 1\
                     AND mac = '%s' AND duid = '%s' AND iaid = '%s'\
                     AND category = '%s' AND type = '%s'" % \
                    (self.table_leases,
                     transactions[transaction_id].mac,
                     transactions[transaction_id].duid,
                     transactions[transaction_id].iaid,
                     category,
                     atype)
        result = self.query(query)
        if result != None:
            if len(result) == 0:
                return(False)
            else:
                return(result[0][0])
        else:
            return(False)

    def check_advertised_prefix(self, transaction_id='', category='', ptype=''):
        """
        check if there is already an advertised prefix for client
        """
        # attributes to identify host and lease
        if cfg.IGNORE_IAID:
            query = "SELECT prefix, length FROM %s WHERE last_message = 1\
                     AND active = 1\
                     AND mac = '%s' AND duid = '%s'\
                     AND category = '%s' AND type = '%s'" % \
                    (self.table_prefixes,
                     transactions[transaction_id].mac,
                     transactions[transaction_id].duid,
                     category,
                     ptype)
        else:
            query = "SELECT prefix, length FROM %s WHERE last_message = 1\
                     AND active = 1\
                     AND mac = '%s' AND duid = '%s' AND iaid = '%s'\
                     AND category = '%s' AND type = '%s'" % \
                    (self.table_prefixes,
                     transactions[transaction_id].mac,
                     transactions[transaction_id].duid,
                     transactions[transaction_id].iaid,
                     category,
                     ptype)
        result = self.query(query)
        if result != None:
            if len(result) == 0:
                return(False)
            else:
                return(result[0][0])
        else:
            return(False)

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
        query = f"DELETE FROM {self.table_leases} WHERE active = 0 AND category = '{category}' AND valid_until < '{now}'"
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
        query = "UPDATE %s SET last_message = 0 WHERE last_message = 1 AND last_update < '%s'" % (self.table_leases, now + 60)
        return self.query(query)

    def unlock_unused_advertised_prefixes(self, now):
        """
            unlock prefixes marked as advertised but apparently never been delivered
            let's say a client should have requested its formerly advertised address after 1 minute
        """
        query = "UPDATE %s SET last_message = 0 WHERE last_message = 1 AND last_update < '%s'" % (self.table_prefixes, now + 60)
        return self.query(query)

    def build_config_from_db(self, transaction_id):
        """
        get client config from db and build the appropriate config objects and indices
        """
        if transactions[transaction_id].client_config_db is None:
            query = "SELECT hostname, mac, duid, class, address, id FROM %s WHERE \
                    hostname = '%s' OR mac LIKE '%%%s%%' OR duid = '%s'" % \
                    (self.table_hosts,\
                     transactions[transaction_id].hostname,\
                     transactions[transaction_id].mac,\
                     transactions[transaction_id].duid)
            answer = self.query(query)

            # add client config which seems to fit to transaction
            transactions[transaction_id].client_config_db = ClientConfigDB()

            # read all sections of config file
            # a section here is a host
            # lowering MAC and DUID information in case they where upper in database
            for host in answer:
                hostname, mac, duid, aclass, address, id = host
                # lower some attributes to comply with values from request
                if mac: mac = listify_option(mac.lower())
                if duid: duid = duid.lower()
                if address: address = listify_option(address.lower())

                transactions[transaction_id].client_config_db.hosts[hostname] = ClientConfig(hostname=hostname,
                                                                                                mac=mac,
                                                                                                duid=duid,
                                                                                                aclass=aclass,
                                                                                                address=address,
                                                                                                id=id)

                # and put the host objects into index
                if transactions[transaction_id].client_config_db.hosts[hostname].MAC:
                    for m in transactions[transaction_id].client_config_db.hosts[hostname].MAC:
                        if not m in transactions[transaction_id].client_config_db.index_mac:
                            transactions[transaction_id].client_config_db.index_mac[m] = [transactions[transaction_id].client_config_db.hosts[hostname]]
                        else:
                            transactions[transaction_id].client_config_db.index_mac[m].append(transactions[transaction_id].client_config_db.hosts[hostname])

                # add DUIDs to IndexDUID
                if not transactions[transaction_id].client_config_db.hosts[hostname].DUID == '':
                    if not transactions[transaction_id].client_config_db.hosts[hostname].DUID in transactions[transaction_id].client_config_db.index_duid:
                        transactions[transaction_id].client_config_db.index_duid[transactions[transaction_id].client_config_db.hosts[hostname].DUID] = [transactions[transaction_id].client_config_db.hosts[hostname]]
                    else:
                        transactions[transaction_id].client_config_db.index_duid[transactions[transaction_id].client_config_db.hosts[hostname].DUID].append(transactions[transaction_id].client_config_db.hosts[hostname])

                # some cleaning
                del host, mac, duid, address, aclass, id

    def get_client_config_by_mac(self, transaction_id):
        """
        get host and its information belonging to that mac
        """
        hosts = list()
        mac = transactions[transaction_id].mac

        if mac in transactions[transaction_id].client_config_db.index_mac:
            hosts.extend(transactions[transaction_id].client_config_db.index_mac[mac])
            return hosts
        else:
            return None


    def get_client_config_by_duid(self, transaction_id):
        """
            get host and its information belonging to that DUID
        """
        # get client config that most probably seems to fit
        hosts = list()
        duid = transactions[transaction_id].duid

        if duid in transactions[transaction_id].client_config_db.index_duid:
            hosts.extend(transactions[transaction_id].client_config_db.index_duid[duid])
            return hosts
        else:
            return None


    def get_client_config_by_hostname(self, transaction_id):
        """
            get host and its information by hostname
        """
        hostname = transactions[transaction_id].hostname
        if hostname in transactions[transaction_id].client_config_db.hosts:
            return [transactions[transaction_id].client_config_db.hosts[hostname]]
        else:
            return None


    def get_client_config(self, hostname='', aclass='', duid='', address=[], mac=[], id=''):
        """
            give back ClientConfig object
        """
        return ClientConfig(hostname=hostname, aclass=aclass, duid=duid, address=address, mac=mac, id=id)


    def store_mac_llip(self, mac, link_local_ip, now):
        """
            store MAC-link-local-ip-mapping
        """
        query = f"SELECT mac FROM macs_llips WHERE mac='{mac}'"
        db_entry = self.query(query)
        # if known already update timestamp of MAC-link-local-ip-mapping
        if not db_entry or db_entry == []:
            query = "INSERT INTO macs_llips (mac, link_local_ip, last_update) VALUES ('%s', '%s', '%s')" % \
                  (mac, link_local_ip, now)
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

                if update_type != False:
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
                            self.query("UPDATE leases SET last_update_new = {0}, "
                                                                  "preferred_until_new = {1}, "
                                                                  "valid_until_new = {2} "
                                                "WHERE address = '{3}'".format(last_update_new,
                                                                               preferred_until_new,
                                                                               valid_until_new,
                                                                               address))
                        print('Converting timestamps of leases succeeded')
                        timestamps_old = self.query('SELECT mac, last_update FROM macs_llips')
                        for timestamp_old in timestamps_old:
                            mac, last_update = timestamp_old
                            last_update_new = last_update.strftime('%s')
                            self.query("UPDATE macs_llips SET last_update_new = {0} "
                                                "WHERE mac = '{1}'".format(last_update_new,
                                                                           mac))
                        print('Converting timestamps of macs_llips succeeded')
                        for table in db_tables:
                            for column in db_tables[table]:
                                self.query(f'ALTER TABLE {table} DROP COLUMN {column}')
                                self.query('ALTER TABLE {0} CHANGE COLUMN {1}_new {1} BIGINT NOT NULL'.format(table, column))
                                print(f'Moving column {column} of table {table} succeeded')

                    if update_type == 'sqlite':
                        for table in db_tables:
                            self.query('ALTER TABLE {0} RENAME TO {0}_old'.format(table))

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
                            self.query("UPDATE leases SET last_update = {0}, "
                                                          "preferred_until = {1}, "
                                                          "valid_until = {2} "
                                                "WHERE address = '{3}'".format(last_update_new,
                                                                               preferred_until_new,
                                                                               valid_until_new,
                                                                               address))
                        print('Converting timestamps of leases succeeded')
                        timestamps_old = self.query('SELECT mac, last_update FROM macs_llips_old')
                        for timestamp_old in timestamps_old:
                            mac, last_update = timestamp_old
                            last_update_new = last_update.strftime('%s')
                            self.query("UPDATE macs_llips SET last_update = {0} "
                                                "WHERE mac = '{1}'".format(last_update_new,
                                                                           mac))
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
        for robustness see http://stackoverflow.com/questions/207981/how-to-enable-mysql-client-auto-re-connect-with-mysqldb
    """

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
                if not 'MySQLdb' in list(sys.modules.keys()):
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
                if not 'psycopg2' in list(sys.modules.keys()):
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