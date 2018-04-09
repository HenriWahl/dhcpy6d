# encoding: utf8
#
# DHCPy6d DHCPv6 Daemon
#
# Copyright (C) 2009-2018 Henri Wahl <h.wahl@ifw-dresden.de>
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
import threading
import ConfigParser
from helpers import *
import os
import pwd
import grp
import traceback
import time


class QueryQueue(threading.Thread):
    '''
        Pump queries around
    '''
    def __init__(self, cfg, store, query_queue, answer_queue):
        threading.Thread.__init__(self, name='QueryQueue')
        self.query_queue = query_queue
        self.answer_queue = answer_queue
        self.store = store
        self.setDaemon(1)


    def run(self):
        '''
            receive queries and ask the DB interface for answers which will be put into
            answer queue
        '''
        while True:
            query = self.query_queue.get()
            try:
                answer = self.store.DBQuery(query)
            except:
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
                answer = ''

            self.answer_queue.put(answer)


class Store(object):
    '''
        abstract class to present MySQL or SQLlite
    '''
    def __init__(self, cfg, query_queue, answer_queue, Transactions, CollectedMACs):
        self.cfg = cfg
        self.query_queue = query_queue
        self.answer_queue = answer_queue
        self.Transactions = Transactions
        self.CollectedMACs = CollectedMACs
        # table names used for database storage - MySQL additionally needs the database name
        self.table_leases = 'leases'
        self.table_prefixes = 'prefixes'
        self.table_macs_llips = 'macs_llips'
        self.table_hosts = 'hosts'
        self.table_routes = 'routes'
        # flag to check if connection is OK
        self.connected = False


    def query(self, query):
        '''
            put queries received into query queue and return the answers from answer queue
        '''
        self.query_queue.put(query)
        answer = self.answer_queue.get()

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
            if not (answer == [] or answer == () or answer == None):
                return answer[0][0]
            else:
                return None
        return (decoration_function)


    @clean_query_answer
    def get_db_version(self):
        '''
        '''
        return(self.query("SELECT item_value FROM meta WHERE item_key = 'version'"))


    def store(self, transaction_id):
        '''
            store lease in lease DB
        '''
        # only if client exists
        if self.Transactions[transaction_id].Client:
            for a in self.Transactions[transaction_id].Client.Addresses:
                if not a.ADDRESS is None:
                    query = "SELECT address FROM %s WHERE address = '%s'" % (self.table_leases, a.ADDRESS)
                    answer = self.query(query)
                    if answer != None:
                        # if address is not leased yet add it
                        if len(answer) == 0:
                            now = int(time.time())
                            query = "INSERT INTO %s (address, active, last_message, preferred_lifetime, valid_lifetime,\
                                     hostname, type, category, ia_type, class, mac, duid, iaid, last_update,\
                                     preferred_until, valid_until) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s',\
                                     '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % \
                                  (self.table_leases,
                                   a.ADDRESS,
                                   1,
                                   self.Transactions[transaction_id].LastMessageReceivedType,
                                   a.PREFERRED_LIFETIME,
                                   a.VALID_LIFETIME,
                                   self.Transactions[transaction_id].Client.Hostname,
                                   a.TYPE,
                                   a.CATEGORY,
                                   a.IA_TYPE,
                                   self.Transactions[transaction_id].Client.Class,
                                   self.Transactions[transaction_id].MAC,
                                   self.Transactions[transaction_id].DUID,
                                   self.Transactions[transaction_id].IAID,
                                   now,
                                   now + a.PREFERRED_LIFETIME,
                                   now + a.VALID_LIFETIME)
                            self.query(query)
                            del now
                        # otherwise update it if not a random address
                        elif a.CATEGORY != 'random':
                            now = int(time.time())
                            query = "UPDATE %s SET active = 1, last_message = %s, preferred_lifetime = '%s',\
                                     valid_lifetime = '%s', hostname = '%s', type = '%s', category = '%s',\
                                     ia_type = '%s', class = '%s', mac = '%s', duid = '%s', iaid = '%s',\
                                     last_update = '%s', preferred_until = '%s', valid_until = '%s'\
                                  WHERE address = '%s'" % \
                                  (self.table_leases,
                                   self.Transactions[transaction_id].LastMessageReceivedType,
                                   a.PREFERRED_LIFETIME,
                                   a.VALID_LIFETIME,
                                   self.Transactions[transaction_id].Client.Hostname,
                                   a.TYPE,
                                   a.CATEGORY,
                                   a.IA_TYPE,
                                   self.Transactions[transaction_id].Client.Class,
                                   self.Transactions[transaction_id].MAC,
                                   self.Transactions[transaction_id].DUID,
                                   self.Transactions[transaction_id].IAID,
                                   now,
                                   now + a.PREFERRED_LIFETIME,
                                   now + a.VALID_LIFETIME,
                                   a.ADDRESS)
                            self.query(query)
                            del now
                        else:
                            # set last message type of random address
                            query = "UPDATE %s SET last_message = '%s', active = 1 WHERE address = '%s'" %\
                                     (self.table_leases, self.Transactions[transaction_id].LastMessageReceivedType,
                                      a.ADDRESS)
                            self.query(query)

            for p in self.Transactions[transaction_id].Client.Prefixes:
                if not p.PREFIX is None:
                    query = "SELECT prefix FROM %s WHERE prefix = '%s'" % (self.table_prefixes, p.PREFIX)
                    answer = self.query(query)
                    if answer != None:
                        # if address is not leased yet add it
                        if len(answer) == 0:
                            now = int(time.time())
                            query = "INSERT INTO %s (prefix, length, active, last_message, preferred_lifetime, valid_lifetime,\
                                     hostname, type, category, class, mac, duid, iaid, last_update,\
                                     preferred_until, valid_until) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',\
                                     '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % \
                                  (self.table_prefixes,
                                   p.PREFIX,
                                   p.LENGTH,
                                   1,
                                   self.Transactions[transaction_id].LastMessageReceivedType,
                                   p.PREFERRED_LIFETIME,
                                   p.VALID_LIFETIME,
                                   self.Transactions[transaction_id].Client.Hostname,
                                   p.TYPE,
                                   p.CATEGORY,
                                   self.Transactions[transaction_id].Client.Class,
                                   self.Transactions[transaction_id].MAC,
                                   self.Transactions[transaction_id].DUID,
                                   self.Transactions[transaction_id].IAID,
                                   now,
                                   now + p.PREFERRED_LIFETIME,
                                   now + p.VALID_LIFETIME)
                            self.query(query)
                            del now
                        # otherwise update it if not a random address
                        elif p.CATEGORY != 'random':
                            now = int(time.time())
                            query = "UPDATE %s SET active = 1, last_message = %s, preferred_lifetime = '%s',\
                                     valid_lifetime = '%s', hostname = '%s', type = '%s', category = '%s',\
                                     class = '%s', mac = '%s', duid = '%s', iaid = '%s',\
                                     last_update = '%s', preferred_until = '%s', valid_until = '%s'\
                                     WHERE prefix = '%s'" % \
                                  (self.table_prefixes,
                                   self.Transactions[transaction_id].LastMessageReceivedType,
                                   p.PREFERRED_LIFETIME,
                                   p.VALID_LIFETIME,
                                   self.Transactions[transaction_id].Client.Hostname,
                                   p.TYPE,
                                   p.CATEGORY,
                                   self.Transactions[transaction_id].Client.Class,
                                   self.Transactions[transaction_id].MAC,
                                   self.Transactions[transaction_id].DUID,
                                   self.Transactions[transaction_id].IAID,
                                   now,
                                   now + p.PREFERRED_LIFETIME,
                                   now + p.VALID_LIFETIME,
                                   p.PREFIX)
                            self.query(query)
                            del now
                        else:
                            # set last message type of random address
                            query = "UPDATE %s SET last_message = '%s', active = 1 WHERE address = '%s'" %\
                                     (self.table_prefixes, self.Transactions[transaction_id].LastMessageReceivedType,
                                      p.PREFIX)
                            self.query(query)
            return True
        # if no client -> False
        return False


    @clean_query_answer
    def store_route(self, prefix, length, router):
        '''
            store route in database to keep track of routes and be able to delete them later
        '''
        query = "SELECT prefix FROM {0} WHERE prefix = '{1}'".format(self.table_routes, prefix)
        if self.query is not None:
            if len(self.query(query)) == 0:
                query = "INSERT INTO {0} VALUES ('{1}', '{2}', '{3}', '{4}')".format(self.table_routes, prefix, length, router, int(time.time()))
                return self.query(query)
            elif len(self.query(query)) == 1:
                query = "UPDATE {0} SET prefix = '{1}', length = '{2}', router = '{3}', last_update = '{4}' WHERE prefix = '{1}'".format(self.table_routes, prefix, length, router, int(time.time()))
                return self.query(query)
            return None
        else:
            return None


    @clean_query_answer
    def get_range_lease_for_recycling(self, prefix='', frange='', trange='', duid='', mac=''):
        '''
            ask DB for last known leases of an already known host to be recycled
            this is most useful for CONFIRM-requests that will get a not-available-answer but get an
            ADVERTISE with the last known-as-good address for a client
            SOLICIT message type is 1
        '''
        query = "SELECT address FROM %s WHERE "\
                "category = 'range' AND "\
                "'%s' <= address AND "\
                "address <= '%s' AND "\
                "duid = '%s' AND "\
                "mac = '%s' AND "\
                "last_message != 1 "\
                "ORDER BY last_update DESC LIMIT 1" %\
                (self.table_leases, prefix+frange, prefix+trange, duid, mac)
        return self.query(query)


    @clean_query_answer
    def get_range_prefix_for_recycling(self, prefix='', length=0, frange='', trange='', duid='', mac=''):
        '''
            ask DB for last known prefixes of an already known host to be recycled
            this is most useful for CONFIRM-requests that will get a not-available-answer but get an
            ADVERTISE with the last known-as-good address for a client
            SOLICIT message type is 1
        '''
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
                 prefix+frange+((128-length)/4)*'0',
                 prefix+trange+((128-length)/4)*'0',
                 str(length),
                 duid,
                 mac)
        return self.query(query)


    @clean_query_answer
    def get_highest_range_lease(self, prefix='', frange='', trange=''):
        '''
            ask DB for highest known leases - if necessary range sensitive
        '''
        query = "SELECT address FROM %s WHERE active = 1 AND "\
                "category = 'range' AND "\
                "'%s' <= address and address <= '%s' ORDER BY address DESC LIMIT 1" %\
                (self.table_leases,
                 prefix+frange,
                 prefix+trange)
        return self.query(query)


    @clean_query_answer
    def get_highest_range_prefix(self, prefix='', length=0, frange='', trange=''):
        '''
            ask DB for highest known prefix - if necessary range sensitive
        '''
        query = "SELECT prefix FROM %s WHERE active = 1 AND "\
                "category = 'range' AND "\
                "'%s' <= prefix AND prefix <= '%s' AND "\
                "length = '%s' ORDER BY prefix DESC LIMIT 1" %\
                (self.table_prefixes,
                    prefix+frange+((128-length)/4)*'0',
                    prefix+trange+((128-length)/4)*'0',
                    str(length))
        return self.query(query)


    @clean_query_answer
    def get_oldest_inactive_range_lease(self, prefix='', frange='', trange=''):
        '''
            ask DB for oldest known inactive lease to minimize chance of collisions
            ordered by valid_until to get leases that are free as long as possible
        '''
        query = "SELECT address FROM %s WHERE active = 0 AND category = 'range' AND "\
                "'%s' <= address AND address <= '%s' ORDER BY valid_until ASC LIMIT 1" %\
                (self.table_leases,
                 prefix+frange,
                 prefix+trange)
        return self.query(query)


    @clean_query_answer
    def get_oldest_inactive_range_prefix(self, prefix='', length=0, frange='', trange=''):
        '''
            ask DB for oldest known inactive prefix to minimize chance of collisions
            ordered by valid_until to get leases that are free as long as possible
        '''
        query = "SELECT prefix FROM %s WHERE active = 0 AND " \
                "category = 'range' AND "\
                "'%s' <= prefix AND prefix <= '%s' AND " \
                "length = '%s' "\
                "ORDER BY valid_until ASC LIMIT 1" %\
                (self.table_prefixes,
                 prefix+frange+((128-length)/4)*'0',
                 prefix+trange+((128-length)/4)*'0',
                 str(length))
        return self.query(query)


    def get_host_lease(self, address):
        '''
            get the hostname, DUID, MAC and IAID to verify a lease to delete its address in the DNS
        '''
        query = "SELECT DISTINCT hostname, duid, mac, iaid FROM {0}} WHERE address='{1}'".format(self.table_leases, address)
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


    def get_inactive_prefixes(self):
        '''
            get unused prefixes to be able to delete their routes
        '''
        query = "SELECT {0}.prefix FROM {0} INNER JOIN routes ON {0}.prefix = {1}.prefix WHERE {0}.active = 0".format(self.table_prefixes, self.table_routes)
        prefixes = self.query(query)
        inactive_prefixes = list()
        for p in prefixes:
            inactive_prefixes.append(p[0])
        return inactive_prefixes


    @clean_query_answer
    def release_lease(self, address):
        '''
            release a lease via setting its active flag to False
            set last_message to 8 because of RELEASE messages having this message id
        '''
        query = "UPDATE %s SET active = 0, last_message = 8, last_update = '%s' WHERE address = '%s'" % (self.table_leases, int(time.time()), address)
        self.query(query)


    @clean_query_answer
    def release_prefix(self, prefix):
        '''
            release a prefix via setting its active flag to False
            set last_message to 8 because of RELEASE messages having this message id
        '''
        query = "UPDATE %s SET active = 0, last_message = 8, last_update = '%s' WHERE prefix = '%s'" % (self.table_prefixes, int(time.time()), prefix)
        self.query(query)


    @clean_query_answer
    def check_number_of_leases(self, prefix='', frange='', trange=''):
        '''
            check how many leases are stored - used to find out if address range has been exceeded
        '''
        query = "SELECT COUNT(address) FROM %s WHERE address LIKE '%s%%' AND "\
                "'%s' <= address AND address <= '%s'" % (self.table_leases,
                                                         prefix,
                                                         prefix+frange,
                                                         prefix+trange)
        return self.query(query)


    @clean_query_answer
    def check_number_of_prefixes(self, prefix='', length=0, frange='', trange=''):
        '''
            check how many leases are stored - used to find out if address range has been exceeded
        '''
        query = "SELECT COUNT(prefix) FROM %s WHERE prefix LIKE '%s%%' AND "\
                "'%s' <= prefix AND prefix <= '%s'" % (self.table_prefixes,
                                                       prefix,
                                                       prefix+frange+((128-length)/4)*'0',
                                                       prefix+trange+((128-length)/4)*'0')
        return self.query(query)


    def check_lease(self, address, transaction_id):
        '''
            check state of a lease for REBIND and RENEW messages
        '''
        # attributes to identify host and lease
        if self.cfg.IGNORE_IAID:
            query = "SELECT DISTINCT hostname, address, type, category, ia_type, class, preferred_until FROM %s WHERE active = 1\
                     AND address = '%s' AND mac = '%s' AND duid = '%s'" % \
                    (self.table_leases, address,
                     self.Transactions[transaction_id].MAC,
                     self.Transactions[transaction_id].DUID)
        else:
            query = "SELECT DISTINCT hostname, address, type, category, ia_type, class, preferred_until FROM %s WHERE active = 1\
                     AND address = '%s' AND mac = '%s' AND duid = '%s' AND iaid = '%s'" % \
                    (self.table_leases, address,
                     self.Transactions[transaction_id].MAC,
                     self.Transactions[transaction_id].DUID,
                     self.Transactions[transaction_id].IAID)

        return self.query(query)


    def check_prefix(self, prefix, length, transaction_id):
        '''
            check state of a prefix for REBIND and RENEW messages
        '''
        # attributes to identify host and lease
        if self.cfg.IGNORE_IAID:
            query = "SELECT DISTINCT hostname, prefix, length, type, category, class, preferred_until FROM %s WHERE active = 1\
                     AND prefix = '%s' AND length = '%s' AND mac = '%s' AND duid = '%s'" % \
                    (self.table_prefixes,
                     prefix,
                     length,
                     self.Transactions[transaction_id].MAC,
                     self.Transactions[transaction_id].DUID)
        else:
            query = "SELECT DISTINCT hostname, prefix, length, type, category, class, preferred_until FROM %s WHERE active = 1\
                     AND prefix = '%s' AND length = '%s' AND mac = '%s' AND duid = '%s' AND iaid = '%s'" % \
                    (self.table_prefixes,
                     prefix,
                     length,
                     self.Transactions[transaction_id].MAC,
                     self.Transactions[transaction_id].DUID,
                     self.Transactions[transaction_id].IAID)
        return self.query(query)


    def check_advertised_lease(self, transaction_id='', category='', atype=''):
        '''
            check if there are already advertised addresses for client
        '''
        # attributes to identify host and lease
        if self.cfg.IGNORE_IAID:
            query = "SELECT address FROM %s WHERE last_message = 1\
                     AND active = 1\
                     AND mac = '%s' AND duid = '%s'\
                     AND category = '%s' AND type = '%s'" % \
                    (self.table_leases,
                     self.Transactions[transaction_id].MAC,
                     self.Transactions[transaction_id].DUID,
                     category,
                     atype)
        else:
            query = "SELECT address FROM %s WHERE last_message = 1\
                     AND active = 1\
                     AND mac = '%s' AND duid = '%s' AND iaid = '%s'\
                     AND category = '%s' AND type = '%s'" % \
                    (self.table_leases,
                     self.Transactions[transaction_id].MAC,
                     self.Transactions[transaction_id].DUID,
                     self.Transactions[transaction_id].IAID,
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
        '''
            check if there is already an advertised prefix for client
        '''
        # attributes to identify host and lease
        if self.cfg.IGNORE_IAID:
            query = "SELECT prefix, length FROM %s WHERE last_message = 1\
                     AND active = 1\
                     AND mac = '%s' AND duid = '%s'\
                     AND category = '%s' AND type = '%s'" % \
                    (self.table_prefixes,
                     self.Transactions[transaction_id].MAC,
                     self.Transactions[transaction_id].DUID,
                     category,
                     ptype)
        else:
            query = "SELECT prefix, length FROM %s WHERE last_message = 1\
                     AND active = 1\
                     AND mac = '%s' AND duid = '%s' AND iaid = '%s'\
                     AND category = '%s' AND type = '%s'" % \
                    (self.table_prefixes,
                     self.Transactions[transaction_id].MAC,
                     self.Transactions[transaction_id].DUID,
                     self.Transactions[transaction_id].IAID,
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


    def release_free_leases(self, timestamp=int(time.time())):
        '''
            release all invalid leases via setting their active flag to False
        '''
        query = "UPDATE %s SET active = 0, last_message = 0 WHERE valid_until < '%s'" % (self.table_leases, timestamp)
        return self.query(query)


    def release_free_prefixes(self, timestamp=int(time.time())):
        '''
            release all invalid prefixes via setting their active flag to False
        '''
        query = "UPDATE %s SET active = 0, last_message = 0 WHERE valid_until < '%s'" % (self.table_prefixes, timestamp)
        return self.query(query)


    def remove_leases(self, category="random", timestamp=int(time.time())):
        '''
            remove all leases of a certain category like random - they will grow the database
            but be of no further use
        '''
        query = "DELETE FROM %s WHERE active = 0 AND category = '%s' AND valid_until < '%s'" % (self.table_leases, category, timestamp)
        return self.query(query)


    def remove_route(self, prefix):
        '''
            remove a route which is not used anymore
        '''
        query = "DELETE FROM {0} WHERE prefix = '{1}'".format(self.table_routes, prefix)
        return self.query(query)


    def unlock_unused_advertised_leases(self, timestamp=int(time.time())):
        '''
            unlock leases marked as advertised but apparently never been delivered
            let's say a client should have requested its formerly advertised address after 1 minute
        '''
        query = "UPDATE %s SET last_message = 0 WHERE last_message = 1 AND last_update < '%s'" % (self.table_leases, timestamp + 60)
        return self.query(query)


    def unlock_unused_advertised_prefixes(self, timestamp=int(time.time())):
        '''
            unlock prefixes marked as advertised but apparently never been delivered
            let's say a client should have requested its formerly advertised address after 1 minute
        '''
        query = "UPDATE %s SET last_message = 0 WHERE last_message = 1 AND last_update < '%s'" % (self.table_prefixes, timestamp + 60)
        return self.query(query)


    def build_config_from_db(self, transaction_id):
        '''
            get client config from db and build the appropriate config objects and indices
        '''
        if self.Transactions[transaction_id].ClientConfigDB == None:
            query = "SELECT hostname, mac, duid, class, address, id FROM %s WHERE \
                    hostname = '%s' OR mac LIKE '%%%s%%' OR duid = '%s'" % \
                    (self.table_hosts,\
                     self.Transactions[transaction_id].Hostname,\
                     self.Transactions[transaction_id].MAC,\
                     self.Transactions[transaction_id].DUID)
            answer = self.query(query)

            # add client config which seems to fit to transaction
            self.Transactions[transaction_id].ClientConfigDB = ClientConfigDB()

            # read all sections of config file
            # a section here is a host
            # lowering MAC and DUID information in case they where upper in database
            for host in answer:
                hostname, mac, duid, aclass, address, id = host
                # lower some attributes to comply with values from request
                if mac: mac = listify_option(mac.lower())
                if duid: duid = duid.lower()
                if address: address = listify_option(address.lower())

                self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname] = ClientConfig(hostname=hostname,\
                                                mac=mac,\
                                                duid=duid,\
                                                aclass=aclass,\
                                                address=address,\
                                                id=id)

                #### in case of various addresses split them...
                ###self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].ADDRESS = listify_option(self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].ADDRESS)

                # and put the host objects into index
                if self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].MAC:
                    for m in self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].MAC:
                        if not m in self.Transactions[transaction_id].ClientConfigDB.IndexMAC:
                            self.Transactions[transaction_id].ClientConfigDB.IndexMAC[m] = [self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname]]
                        else:
                            self.Transactions[transaction_id].ClientConfigDB.IndexMAC[m].append(self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname])

                # add DUIDs to IndexDUID
                if not self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].DUID == '':
                    if not self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].DUID in self.Transactions[transaction_id].ClientConfigDB.IndexDUID:
                        self.Transactions[transaction_id].ClientConfigDB.IndexDUID[self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].DUID] = [self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname]]
                    else:
                        self.Transactions[transaction_id].ClientConfigDB.IndexDUID[self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].DUID].append(self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname])

                # some cleaning
                del host, mac, duid, address, aclass, id


    def get_client_config_by_mac(self, transaction_id):
        '''
            get host and its information belonging to that mac
        '''
        hosts = list()
        mac = self.Transactions[transaction_id].MAC

        if mac in self.Transactions[transaction_id].ClientConfigDB.IndexMAC:
            hosts.extend(self.Transactions[transaction_id].ClientConfigDB.IndexMAC[mac])
            return hosts
        else:
            return None


    def get_client_config_by_duid(self, transaction_id):
        '''
            get host and its information belonging to that DUID
        '''
        # get client config that most probably seems to fit
        hosts = list()
        duid = self.Transactions[transaction_id].DUID

        if duid in self.Transactions[transaction_id].ClientConfigDB.IndexDUID:
            hosts.extend(self.Transactions[transaction_id].ClientConfigDB.IndexDUID[duid])
            return hosts
        else:
            return None


    def get_client_config_by_hostname(self, transaction_id):
        '''
            get host and its information by hostname
        '''
        hostname = self.Transactions[transaction_id].Hostname
        if hostname in self.Transactions[transaction_id].ClientConfigDB.Hosts:
            return [self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname]]
        else:
            return None


    def get_client_config(self, hostname='', aclass='', duid='', address=[], mac=[], id=''):
        '''
            give back ClientConfig object
        '''
        return ClientConfig(hostname=hostname, aclass=aclass, duid=duid, address=address, mac=mac, id=id)


    def store_mac_llip(self, mac, link_local_ip):
        '''
            store MAC-link-local-ip-mapping
        '''
        query = "SELECT mac FROM macs_llips WHERE mac='%s'" % (mac)
        db_entry = self.query(query)
        # if known already update timestamp of MAC-link-local-ip-mapping
        if not db_entry or db_entry == []:
            query = "INSERT INTO macs_llips (mac, link_local_ip, last_update) VALUES ('%s', '%s', '%s')" % \
                  (mac, link_local_ip, int(time.time()))
            self.query(query)
        else:
            query = "UPDATE macs_llips SET link_local_ip = '%s', last_update = '%s' WHERE mac = '%s'" % (link_local_ip, int(time.time()), mac)
            self.query(query)

    @clean_query_answer
    def get_dynamic_prefix(self):
        query = "SELECT item_value FROM meta WHERE item_key = 'dynamic_prefix'"
        return self.query(query)


    def store_dynamic_prefix(self, prefix):
        '''
            store dynamic prefix to be persistent after restart of dhcpy6d
        '''
        query = "SELECT item_value FROM meta WHERE item_key = 'dynamic_prefix'"
        db_entry = self.query(query)

        # if already existing just update dynamic prefix
        if not db_entry or db_entry == []:
            query = "INSERT INTO meta (item_key, item_value) VALUES ('%s', '%s')" % ('dynamic_prefix', prefix)
            self.query(query)
        else:
            query = "UPDATE meta SET item_value = '%s' WHERE item_key = 'dynamic_prefix'" % (prefix)
            self.query(query)


    def CollectMACsFromDB(self):
        '''
            collect all known MACs and link local addresses from database at startup
            to reduce attempts to read neighbor cache
        '''
        query = 'SELECT link_local_ip, mac FROM %s' % (self.table_macs_llips)
        answer = self.query(query)
        if answer:
            for m in answer:
                try:
                    # m[0] is LLIP, m[1] is the matching MAC
                    # interface is ignored and timestamp comes with instance of NeighborCacheRecord()
                    self.CollectedMACs[m[0]] = NeighborCacheRecord(llip=m[0], mac=m[1])
                except Exception, err:
                    #Log("ERROR: CollectMACsFromDB(): " + str(err))
                    print err
                    traceback.print_exc(file=sys.stdout)
                    sys.stdout.flush()
                    return None


    def DBQuery(self, query):
        '''
            no not execute query on DB - dummy
        '''
        # return empty tuple as dummy
        return ()


    def LegacyAdjustments(self):
        '''
            adjust some existing data to work with newer versions of dhcpy6d
        '''
        try:
            if self.query('SELECT last_message FROM leases LIMIT 1') == None:
                # row 'last_message' in tables 'leases' does not exist yet, comes with version 0.1.6
                self.query('ALTER TABLE leases ADD last_message INT NOT NULL DEFAULT 0')
                print "Adding row 'last_message' to table 'leases' in volatile storage succeeded."
        except:
            print "\n'ALTER TABLE leases ADD last_message INT NOT NULL DEFAULT 0' on volatile database failed."
            print 'Please apply manually or grant necessary permissions.\n'
            sys.exit(1)

        # after 0.4.3 with working PostgreSQL support the timestamps have to be stores in epoch seconds, not datetime
        # also after 0.4.3 there will be a third table containing meta information - for a first start it should contain
        # a database version number
        try:
            try:
                # only newer databases contain a version number - starting with 1
                if self.get_db_version() == None:
                    # add table containing meta information like version of database scheme
                    db_operations = ['CREATE TABLE meta (item_key varchar(255) NOT NULL,\
                                      item_value varchar(255) NOT NULL, PRIMARY KEY (item_key))',
                                     "INSERT INTO meta (item_key, item_value) VALUES ('version', '1')"]
                    for db_operation in db_operations:
                        self.query(db_operation)
                        print '{0} in volatile storage succeded.'.format(db_operation)
            except:
                print "\n{0} on volatile database failed.".format(db_operation)
                print 'Please apply manually or grant necessary permissions.\n'
                sys.exit(1)
        except:
            print '\nSomething went wrong when retrieving version from database.\n'
            sys.exit(1)

        # find out if timestamps still are in datetime format - applies only to sqlite and mysql anyway
        if self.cfg.STORE_VOLATILE in ['sqlite', 'mysql']:
            db_datetime_test = self.query('SELECT last_update FROM leases LIMIT 1')
            if len(db_datetime_test) > 0:
                import datetime

                # flag to find out which update has to be done
                update_type = False

                # MySQL
                if type(db_datetime_test[0][0]) is datetime.datetime:
                    update_type = 'mysql'

                # SQLite
                if type(db_datetime_test[0][0]) is unicode:
                    if ' ' in db_datetime_test[0][0]:
                        update_type = 'sqlite'

                if update_type != False:
                    # add new columns with suffix *_new
                    db_tables = {'leases': ['last_update', 'preferred_until', 'valid_until'],
                                 'macs_llips': ['last_update']}

                    if update_type == 'mysql':
                        for table in db_tables:
                            for column in db_tables[table]:
                                self.query('ALTER TABLE {0} ADD COLUMN {1}_new bigint NOT NULL'.format(table, column))
                                print 'ALTER TABLE {0} ADD COLUMN {1}_new bigint NOT NULL succeeded'.format(table, column)
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
                        print 'Converting timestamps of leases succeeded'
                        timestamps_old = self.query('SELECT mac, last_update FROM macs_llips')
                        for timestamp_old in timestamps_old:
                            mac, last_update = timestamp_old
                            last_update_new = last_update.strftime('%s')
                            self.query("UPDATE macs_llips SET last_update_new = {0} "
                                                "WHERE mac = '{1}'".format(last_update_new,
                                                                           mac))
                        print 'Converting timestamps of macs_llips succeeded'
                        for table in db_tables:
                            for column in db_tables[table]:
                                self.query('ALTER TABLE {0} DROP COLUMN {1}'.format(table, column))
                                self.query('ALTER TABLE {0} CHANGE COLUMN {1}_new {1} BIGINT NOT NULL'.format(table, column))
                                print 'Moving column {0} of table {1} succeeded'.format(column, table)

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
                                self.query('ALTER TABLE {0} ADD COLUMN {1} bigint'.format(table, column))

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
                        print 'Converting timestamps of leases succeeded'
                        timestamps_old = self.query('SELECT mac, last_update FROM macs_llips_old')
                        for timestamp_old in timestamps_old:
                            mac, last_update = timestamp_old
                            last_update_new = last_update.strftime('%s')
                            self.query("UPDATE macs_llips SET last_update = {0} "
                                                "WHERE mac = '{1}'".format(last_update_new,
                                                                           mac))
                        print 'Converting timestamps of macs_llips succeeded'

        # Extend volatile database to handle prefixes - comes with database version 2
        if int(self.get_db_version()) < 2:
            if self.cfg.STORE_VOLATILE in ['sqlite', 'mysql']:
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

            elif self.cfg.STORE_VOLATILE == 'postgresql':
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
            print "Adding table 'prefixes' succeeded"

        # Extend volatile database to handle routes - comes with database version 3
        if int(self.get_db_version()) < 3:
            if self.cfg.STORE_VOLATILE in ['sqlite', 'mysql']:
                self.query('CREATE TABLE routes (\
                              prefix varchar(32) NOT NULL,\
                              length tinyint(4) NOT NULL,\
                              router varchar(32) NOT NULL,\
                              last_update bigint NOT NULL,\
                              PRIMARY KEY (prefix)\
                            )')

            elif self.cfg.STORE_VOLATILE == 'postgresql':
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
            print "Adding table 'routes' succeeded"


class SQLite(Store):
    '''
        file-based SQLite database, might be an option for single installations
    '''
    def __init__(self, cfg, query_queue, answer_queue, Transactions, CollectedMACs, storage_type='volatile'):

        Store.__init__(self, cfg, query_queue, answer_queue, Transactions, CollectedMACs)
        self.connection = None

        try:
            self.DBConnect(storage_type)
        except:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()


    def DBConnect(self, storage_type='volatile'):
        '''
            Initialize DB connection
        '''

        import sqlite3

        try:
            if storage_type == 'volatile':
                storage = self.cfg.STORE_SQLITE_VOLATILE
                # set ownership of storage file according to settings
                os.chown(self.cfg.STORE_SQLITE_VOLATILE, pwd.getpwnam(self.cfg.USER).pw_uid, grp.getgrnam(self.cfg.GROUP).gr_gid)
            if storage_type == 'config':
                storage = self.cfg.STORE_SQLITE_CONFIG
            self.connection = sqlite3.connect(storage, check_same_thread = False)
            self.cursor = self.connection.cursor()
            self.connected = True
        except:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            return None


    def DBQuery(self, query):
        '''
            execute query on DB
        '''
        try:
            answer = self.cursor.execute(query)
            # commit only if explicitly wanted
            if query.startswith('INSERT'):
                self.connection.commit()
            elif query.startswith('UPDATE'):
                self.connection.commit()
            elif query.startswith('DELETE'):
                self.connection.commit()
            self.connected = True
        except Exception, err:
            self.connected = False
            print err
            return None

        return answer.fetchall()


class Textfile(Store):
    '''
        client config in text files
    '''
    def __init__(self, cfg, query_queue, answer_queue, Transactions, CollectedMACs):
        Store.__init__(self, cfg, query_queue, answer_queue, Transactions, CollectedMACs)
        self.connection = None

        # store config information of hosts
        self.Hosts = dict()
        self.IndexMAC = dict()
        self.IndexDUID = dict()

        # store IDs for ID-based hosts to check if there are duplicates
        self.IDs = dict()

        # instantiate a Configparser
        config = ConfigParser.ConfigParser()
        config.read(self.cfg.STORE_FILE_CONFIG)

        # read all sections of config file
        # a section here is a host
        for section in config.sections():
            self.Hosts[section] = ClientConfig()
            for item in config.items(section):
                # lowercase all MAC addresses, DUIDs and IPv6 addresses
                if item[0].upper() in ['MAC', 'DUID', 'ADDRESS']:
                    self.Hosts[section].__setattr__(item[0].upper(), str(item[1]).lower())
                else:
                    self.Hosts[section].__setattr__(item[0].upper(), str(item[1]))

            # Test if host has ID
            if self.Hosts[section].CLASS in cfg.CLASSES:
                for a in cfg.CLASSES[self.Hosts[section].CLASS].ADDRESSES:
                    if cfg.ADDRESSES[a].CATEGORY == 'id' and self.Hosts[section].ID == '':
                        error_exit("Textfile client configuration: No ID given for client '%s'" % (self.Hosts[section].HOSTNAME))
            else:
                error_exit("Textfile client configuration: Class '%s' of host '%s' is not defined" % (self.Hosts[section].CLASS, self.Hosts[section].HOSTNAME))

            if self.Hosts[section].ID != '':
                if self.Hosts[section].ID in self.IDs.keys():
                    error_exit("Textfile client configuration: ID '%s' of client '%s' is already used by '%s'." % (self.Hosts[section].ID, self.Hosts[section].HOSTNAME, self.IDs[self.Hosts[section].ID]))
                else:
                    self.IDs[self.Hosts[section].ID] = self.Hosts[section].HOSTNAME

            # in case of various MAC addresses split them...
            self.Hosts[section].MAC = listify_option(self.Hosts[section].MAC)

            # in case of various fixed addresses split them and avoid decompressing of ':'...
            self.Hosts[section].ADDRESS = listify_option(self.Hosts[section].ADDRESS)

            # Decompress IPv6-Addresses
            if self.Hosts[section].ADDRESS != None:
                self.Hosts[section].ADDRESS =  map(lambda x: decompress_ip6(x), self.Hosts[section].ADDRESS)

            # and put the host objects into index
            if self.Hosts[section].MAC:
                for m in self.Hosts[section].MAC:
                    if not m in self.IndexMAC:
                        self.IndexMAC[m] = [self.Hosts[section]]
                    else:
                        self.IndexMAC[m].append(self.Hosts[section])

            # add DUIDs to IndexDUID
            if not self.Hosts[section].DUID == '':
                if not self.Hosts[section].DUID in self.IndexDUID:
                    self.IndexDUID[self.Hosts[section].DUID] = [self.Hosts[section]]
                else:
                    self.IndexDUID[self.Hosts[section].DUID].append(self.Hosts[section])

        # not very meaningful in case of databaseless textfile config but for completeness
        self.connected = True


    def get_client_config_by_mac(self, transaction_id):
        '''
            get host(s?) and its information belonging to that mac
        '''
        hosts = list()
        mac = self.Transactions[transaction_id].MAC
        if mac in self.IndexMAC:
            hosts.extend(self.IndexMAC[mac])
            return hosts
        else:
            return None


    def get_client_config_by_duid(self, transaction_id):
        '''
            get host and its information belonging to that DUID
        '''
        hosts = list()
        duid = self.Transactions[transaction_id].DUID
        if duid in self.IndexDUID:
            hosts.extend(self.IndexDUID[duid])
            return hosts
        else:
            return None


    def get_client_config_by_hostname(self, transaction_id):
        '''
            get host and its information by hostname
        '''
        hostname = self.Transactions[transaction_id].Hostname
        if hostname in self.Hosts:
            return [self.Hosts[hostname]]
        else:
            return None


    def get_client_config(self, hostname='', aclass='', duid='', address=[], mac=[], id=''):
        '''
            give back ClientConfig object
        '''
        return ClientConfig(hostname=hostname, aclass=aclass, duid=duid, address=address, mac=mac, id=id)


class ClientConfig(object):
    '''
        static client settings object to be stuffed into Hosts dict of Textfile store
    '''
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


class ClientConfigDB(object):
    '''
        class for storing client config snippet from DB - used in SQLite and MySQL Storage
    '''
    def __init__(self):
        self.Hosts = dict()
        self.IndexMAC = dict()
        self.IndexDUID = dict()


class DB(Store):
    '''
        MySQL and PostgreSQL database interface
        for robustness see http://stackoverflow.com/questions/207981/how-to-enable-mysql-client-auto-re-connect-with-mysqldb
    '''

    def __init__(self, cfg, query_queue, answer_queue, Transactions, CollectedMACs):
        Store.__init__(self, cfg, query_queue, answer_queue, Transactions, CollectedMACs)
        self.connection = None
        try:
            self.DBConnect()
        except Exception, err:
            print err


    def DBConnect(self):
        '''
            Connect to database server according to database type
        '''
        if self.cfg.STORE_CONFIG == 'mysql' or self.cfg.STORE_VOLATILE == 'mysql':
            try:
                import MySQLdb
            except:
                error_exit('ERROR: Cannot find module MySQLdb. Please install to proceed.')
            try:
                self.connection = MySQLdb.connect(host=self.cfg.STORE_DB_HOST,
                                                   db=self.cfg.STORE_DB_DB,
                                                   user=self.cfg.STORE_DB_USER,
                                                   passwd=self.cfg.STORE_DB_PASSWORD)
                self.connection.autocommit(True)
                self.cursor = self.connection.cursor()
                self.connected = True
            except:
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
                self.connected = False

        elif self.cfg.STORE_CONFIG == 'postgresql' or self.cfg.STORE_VOLATILE == 'postgresql':
            try:
                import psycopg2
            except:
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
                error_exit('ERROR: Cannot find module psycopg2. Please install to proceed.')
            try:
                self.connection = psycopg2.connect(host=self.cfg.STORE_DB_HOST,
                                                   database=self.cfg.STORE_DB_DB,
                                                   user=self.cfg.STORE_DB_USER,
                                                   passwd=self.cfg.STORE_DB_PASSWORD)
                self.cursor = self.connection.cursor()
                self.connected = True
            except:
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
                self.connected = False
        return self.connected


    def DBQuery(self, query):
        try:
            self.cursor.execute(query)
        except Exception as err:
            # try to reestablish database connection
            print 'Error: {0}'.format(str(err))
            if not self.DBConnect():
                return None
            else:
                try:
                    self.cursor.execute(query)
                except:
                    traceback.print_exc(file=sys.stdout)
                    sys.stdout.flush()
                    self.connected = False
                    return None

        result = self.cursor.fetchall()
        return result


class DBMySQL(DB):

    def DBConnect(self):
        '''
            Connect to database server according to database type
        '''
        try:
            import MySQLdb
        except:
            error_exit('ERROR: Cannot find module MySQLdb. Please install to proceed.')
        try:
            self.connection = MySQLdb.connect(host=self.cfg.STORE_DB_HOST,\
                                               db=self.cfg.STORE_DB_DB,\
                                               user=self.cfg.STORE_DB_USER,\
                                               passwd=self.cfg.STORE_DB_PASSWORD)
            self.connection.autocommit(True)
            self.cursor = self.connection.cursor()
            self.connected = True
        except:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            self.connected = False

        return self.connected


class DBPostgreSQL(DB):

    def DBConnect(self):
        '''
            Connect to database server according to database type
        '''
        try:
            import psycopg2
        except:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            error_exit('ERROR: Cannot find module psycopg2. Please install to proceed.')
        try:
            self.connection = psycopg2.connect(host=self.cfg.STORE_DB_HOST,\
                                               database=self.cfg.STORE_DB_DB,\
                                               user=self.cfg.STORE_DB_USER,\
                                               password=self.cfg.STORE_DB_PASSWORD)
            self.connection.autocommit=True
            self.cursor = self.connection.cursor()
            self.connected = True
        except:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            self.connected = False
        return self.connected


    def DBQuery(self, query):
        try:
            self.cursor.execute(query)
        except Exception as err:
            # try to reestablish database connection
            print 'Error: {0}'.format(str(err))
            if not self.DBConnect():
                return None
            else:
                try:
                    self.cursor.execute(query)
                except:
                    traceback.print_exc(file=sys.stdout)
                    sys.stdout.flush()
                    self.connected = False
                    return None
        try:
            result = self.cursor.fetchall()
        # quite probably a psycopg2.ProgrammingError occurs here
        # which should be caught by except psycopg2.ProgrammingError
        # but psycopg2 is not known here
        except Exception:
            return None
        return result
