# DHCPy6d DHCPv6 Daemon
#
# Copyright (C) 2009-2019 Henri Wahl <h.wahl@ifw-dresden.de>
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

import grp
import configparser
import os
import pwd
import sys
import threading
import traceback

from ..config import cfg
from ..globals import (collected_macs,
                       config_answer_queue,
                       config_query_queue,
                       config_store,
                       volatile_answer_queue,
                       volatile_query_queue,
                       volatile_store,
                       transactions)
from ..helpers import (decompress_ip6,
                      error_exit,
                      listify_option,
                      NeighborCacheRecord)
from ..log import log
from .store import (ClientConfig,
                    ClientConfigDB,
                    Store)

class QueryQueue(threading.Thread):
    """
    Pump queries around
    """
    def __init__(self, store, query_queue, answer_queue):
        threading.Thread.__init__(self, name='query_queue')
        self.query_queue = query_queue
        self.answer_queue = answer_queue
        self.store = store
        self.setDaemon(1)

    def run(self):
        """
        receive queries and ask the DB interface for answers which will be put into
        answer queue
        """
        while True:
            query = self.query_queue.get()
            try:
                answer = self.store.DBQuery(query)
            except Exception as error:
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
                answer = error

            self.answer_queue.put({query: answer})




class SQLite(Store):
    """
        file-based SQLite database, might be an option for single installations
    """
    def __init__(self, query_queue, answer_queue, storage_type='volatile'):

        Store.__init__(self, query_queue, answer_queue)
        self.connection = None

        try:
            self.DBConnect(storage_type)
        except:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()


    def DBConnect(self, storage_type='volatile'):
        """
            Initialize DB connection
        """
        if not 'sqlite3' in list(sys.modules.keys()):
            import sqlite3

        try:
            if storage_type == 'volatile':
                storage = cfg.STORE_SQLITE_VOLATILE
                # set ownership of storage file according to settings
                os.chown(cfg.STORE_SQLITE_VOLATILE, pwd.getpwnam(cfg.USER).pw_uid, grp.getgrnam(cfg.GROUP).gr_gid)
            if storage_type == 'config':
                storage = cfg.STORE_SQLITE_CONFIG
            self.connection = sys.modules['sqlite3'].connect(storage, check_same_thread = False)
            self.cursor = self.connection.cursor()
            self.connected = True
        except:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            return None


    def DBQuery(self, query):
        """
            execute query on DB
        """
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
        except sys.modules['sqlite3'].IntegrityError:
            return 'IntegrityError'
        except Exception as err:
            self.connected = False
            print(err)
            return None

        return answer.fetchall()


class Textfile(Store):
    """
        client config in text files
    """
    def __init__(self, cfg, query_queue, answer_queue, transactions, collected_macs):
        Store.__init__(self, cfg, query_queue, answer_queue, transactions, collected_macs)
        self.connection = None

        # store config information of hosts
        self.Hosts = dict()
        self.IndexMAC = dict()
        self.IndexDUID = dict()

        # store IDs for ID-based hosts to check if there are duplicates
        self.IDs = dict()

        # instantiate a Configparser
        config = configparser.ConfigParser()
        config.read(cfg.STORE_FILE_CONFIG)

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
                if self.Hosts[section].ID in list(self.IDs.keys()):
                    error_exit("Textfile client configuration: ID '%s' of client '%s' is already used by '%s'." % (self.Hosts[section].ID, self.Hosts[section].HOSTNAME, self.IDs[self.Hosts[section].ID]))
                else:
                    self.IDs[self.Hosts[section].ID] = self.Hosts[section].HOSTNAME

            # in case of various MAC addresses split them...
            self.Hosts[section].MAC = listify_option(self.Hosts[section].MAC)

            # in case of various fixed addresses split them and avoid decompressing of ':'...
            self.Hosts[section].ADDRESS = listify_option(self.Hosts[section].ADDRESS)

            # Decompress IPv6-Addresses
            if self.Hosts[section].ADDRESS != None:
                self.Hosts[section].ADDRESS =  [decompress_ip6(x) for x in self.Hosts[section].ADDRESS]

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
        """
            get host(s?) and its information belonging to that mac
        """
        hosts = list()
        mac = transactions[transaction_id].MAC
        if mac in self.IndexMAC:
            hosts.extend(self.IndexMAC[mac])
            return hosts
        else:
            return None


    def get_client_config_by_duid(self, transaction_id):
        """
            get host and its information belonging to that DUID
        """
        hosts = list()
        duid = transactions[transaction_id].DUID
        if duid in self.IndexDUID:
            hosts.extend(self.IndexDUID[duid])
            return hosts
        else:
            return None


    def get_client_config_by_hostname(self, transaction_id):
        """
            get host and its information by hostname
        """
        hostname = transactions[transaction_id].Hostname
        if hostname in self.Hosts:
            return [self.Hosts[hostname]]
        else:
            return None


    def get_client_config(self, hostname='', aclass='', duid='', address=[], mac=[], id=''):
        """
            give back ClientConfig object
        """
        return ClientConfig(hostname=hostname, aclass=aclass, duid=duid, address=address, mac=mac, id=id)


# class ClientConfig:
#     """
#         static client settings object to be stuffed into Hosts dict of Textfile store
#     """
#     def __init__(self, hostname='', aclass='default', duid='', address=None, mac=None, id=''):
#         self.HOSTNAME = hostname
#         # MACs
#         self.MAC = mac
#         # fixed addresses
#         if address:
#             self.ADDRESS = list()
#             if type(address) == list:
#                 addresses = address
#             else:
#                 addresses = listify_option(address)
#             for a in addresses:
#                 self.ADDRESS.append(decompress_ip6(a))
#         else:
#             self.ADDRESS = None
#         self.CLASS = aclass
#         self.ID = id
#         self.DUID = duid
#
#
# class ClientConfigDB:
#     """
#         class for storing client config snippet from DB - used in SQLite and MySQL Storage
#     """
#     def __init__(self):
#         self.Hosts = dict()
#         self.IndexMAC = dict()
#         self.IndexDUID = dict()


class DB(Store):
    """
        MySQL and PostgreSQL database interface
        for robustness see http://stackoverflow.com/questions/207981/how-to-enable-mysql-client-auto-re-connect-with-mysqldb
    """

    def __init__(self, cfg, query_queue, answer_queue, transactions, collected_macs):
        Store.__init__(self, cfg, query_queue, answer_queue, transactions, collected_macs)
        self.connection = None
        try:
            self.DBConnect()
        except Exception as err:
            print(err)


    def DBConnect(self):
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


class DBMySQL(DB):

    def DBConnect(self):
        """
            Connect to database server according to database type
        """
        try:
            if not 'MySQLdb' in list(sys.modules.keys()):
                import MySQLdb
        except:
            error_exit('ERROR: Cannot find module MySQLdb. Please install to proceed.')
        try:
            self.connection = sys.modules['MySQLdb'].connect(host=cfg.STORE_DB_HOST,\
                                               db=cfg.STORE_DB_DB,\
                                               user=cfg.STORE_DB_USER,\
                                               passwd=cfg.STORE_DB_PASSWORD)
            self.connection.autocommit(True)
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
        except sys.modules['MySQLdb'].IntegrityError:
            return 'IntegrityError'
        except Exception as err:
            # try to reestablish database connection
            print('Error: {0}'.format(str(err)))
            print('Query: {0}'.format(query))
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


class DBPostgreSQL(DB):

    def DBConnect(self):
        """
            Connect to database server according to database type
        """
        try:
            if not 'psycopg2' in list(sys.modules.keys()):
                import psycopg2
        except:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            error_exit('ERROR: Cannot find module psycopg2. Please install to proceed.')
        try:
            self.connection = sys.modules['psycopg2'].connect(host=cfg.STORE_DB_HOST,\
                                               database=cfg.STORE_DB_DB,\
                                               user=cfg.STORE_DB_USER,\
                                               password=cfg.STORE_DB_PASSWORD)
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
            print('Error: {0}'.format(str(err)))
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

# store
# because of thread trouble there should not be too much db connections at once
# so we need to use the queryqueue way - subject to change
# source of configuration of hosts
# use client configuration only if needed
def initialize_stores():
    if cfg.STORE_CONFIG:
        if cfg.STORE_CONFIG == 'file':
            config_store = Textfile(config_query_queue, config_answer_queue)
        if cfg.STORE_CONFIG == 'mysql':
            config_store = DBMySQL(config_query_queue, config_answer_queue)
        if cfg.STORE_CONFIG == 'postgresql':
            config_store = DBPostgreSQL(config_query_queue, config_answer_queue)
        if cfg.STORE_CONFIG == 'sqlite':
            config_store = SQLite(config_query_queue, config_answer_queue, storage_type='config')
    else:
        # dummy configstore if no client config is needed
        config_store = Store(config_query_queue, config_answer_queue)
        # 'none' store is always connected
        config_store.connected = True

    # storage for changing data like leases, LLIPs, DUIDs etc.
    if cfg.STORE_VOLATILE == 'mysql':
        volatile_store = DBMySQL(volatile_query_queue, volatile_answer_queue)
    if cfg.STORE_VOLATILE == 'postgresql':
        volatile_store = DBPostgreSQL(volatile_query_queue, volatile_answer_queue)
    if cfg.STORE_VOLATILE == 'sqlite':
        volatile_store = SQLite(volatile_query_queue, volatile_answer_queue, storage_type='volatile')

    # do not start if no database connection exists
    if not config_store.connected:
        print('\nConfiguration database is not connected!\n')
        sys.exit(1)
    if not volatile_store.connected:
        print('\nDatabase for volatile data is not connected!\n')
        sys.exit(1)