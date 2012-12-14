# encoding: utf8
#
# storage machinery:
# - store volatile info like leases
# - get stored configuratiion info for clients
#

import sys
import datetime
import threading
import ConfigParser
from Helpers import *


class QueryQueue(threading.Thread):
    """
    Pump queries around
    """
    def __init__(self, cfg, store, queryqueue, answerqueue):
        threading.Thread.__init__(self, name="QueryQueue")
        self.queryqueue = queryqueue
        self.answerqueue = answerqueue
        self.store = store
        self.setDaemon(1) 
        

    def run(self):
        """
        receive queries and ask the DB interface for answers which will be put into
        answer queue
        """
        while True:
            query = self.queryqueue.get()
            try:
                answer = self.store.DBQuery(query)
            except:
                import traceback
                traceback.print_exc(file=sys.stdout)
                answer = ""

            self.answerqueue.put(answer)
            
    
class Store(object):
    """
    abstract class to present MySQL or SQLlite
    """
    def __init__(self, cfg, queryqueue, answerqueue, Transactions, CollectedMACs):
        self.cfg = cfg
        self.queryqueue = queryqueue
        self.answerqueue = answerqueue
        self.Transactions = Transactions
        self.CollectedMACs = CollectedMACs
        # table names used for database storage - MySQL additionally needs the database name
        self.table_leases = "leases"
        self.table_macs_llips = "macs_llips"
        self.table_hosts = "hosts"
        # flag to check if connection is OK
        self.connected = False


    def query(self, query):
        """
        put queries received into query queue and return the answers from answer queue
        """
        self.queryqueue.put(query)
        answer = self.answerqueue.get()

        return answer
    
    
    def store_lease(self, transaction_id):
        """
        store lease in lease DB
        """
        # only if client exists
        if self.Transactions[transaction_id].Client:
            for a in self.Transactions[transaction_id].Client.Addresses:
                ###query = "SELECT address FROM %s WHERE address = '%s'" % (self.table_leases, "".join(DecompressIP6(a.ADDRESS)))           
                query = "SELECT address FROM %s WHERE address = '%s'" % (self.table_leases, a.ADDRESS)           
                answer = self.query(query)
                if answer:
                    # if address is not leased yet add it
                    if len(answer) == 0:
                        query = "INSERT INTO %s (address, active, preferred_lifetime, valid_lifetime, hostname, type, category, ia_type, class, mac, duid, iaid, last_update, preferred_until, valid_until) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % \
                              (self.table_leases,\
                               a.ADDRESS,\
                               1,\
                               a.PREFERRED_LIFETIME,\
                               a.VALID_LIFETIME,\
                               self.Transactions[transaction_id].Client.Hostname,\
                               a.TYPE,\
                               a.CATEGORY,\
                               a.IA_TYPE,\
                               self.Transactions[transaction_id].Client.Class,\
                               self.Transactions[transaction_id].MAC,\
                               self.Transactions[transaction_id].DUID,\
                               self.Transactions[transaction_id].IAID,\
                               datetime.datetime.now(),\
                               datetime.datetime.now() + datetime.timedelta(seconds=int(a.PREFERRED_LIFETIME)),\
                               datetime.datetime.now() + datetime.timedelta(seconds=int(a.VALID_LIFETIME)))
                        answer = self.query(query)
                    # otherwise update it if not a random address
                    elif a.CATEGORY != "random":
                        query = "UPDATE %s SET active = '%s', preferred_lifetime = '%s', valid_lifetime = '%s',\
                              hostname = '%s', type = '%s', category = '%s', ia_type = '%s', class = '%s', mac = '%s',\
                              duid = '%s', iaid = '%s', last_update = '%s', preferred_until = '%s',\
                              valid_until = '%s'\
                              WHERE address = '%s'" % \
                              (self.table_leases,\
                               1,\
                               a.PREFERRED_LIFETIME,\
                               a.VALID_LIFETIME,\
                               self.Transactions[transaction_id].Client.Hostname,\
                               a.TYPE,\
                               a.CATEGORY,\
                               a.IA_TYPE,\
                               self.Transactions[transaction_id].Client.Class,\
                               self.Transactions[transaction_id].MAC,\
                               self.Transactions[transaction_id].DUID,\
                               self.Transactions[transaction_id].IAID,\
                               datetime.datetime.now(),\
                               datetime.datetime.now() + datetime.timedelta(seconds=int(a.PREFERRED_LIFETIME)),\
                               datetime.datetime.now() + datetime.timedelta(seconds=int(a.VALID_LIFETIME)),\
                               a.ADDRESS)            
                        
                        answer = self.query(query)
            return True
        # if no client -> False
        return False   
    
    
    def get_range_lease(self, active=1, prefix="", frange="", trange=""):
        """
        ask DB for last known leases - active and inactive and if necessary range sensitive
        """ 
        if frange == trange == "":
            query = "SELECT address FROM %s WHERE active = %s AND address LIKE '%s%%' ORDER BY address DESC LIMIT 1" % (self.table_leases, active, prefix)           
        else:
            query =  "SELECT address FROM %s WHERE active = %s AND '%s' <= address and address <= '%s' ORDER BY address DESC LIMIT 1" %\
                  (self.table_leases, active, prefix+frange, prefix+trange) 
        answer = self.query(query)
        
        # SQLite returns list, MySQL tuple - in case someone wonders here...
        if not (answer == [] or answer == () or answer == None):
            return answer[0][0]
        else:
            return None
        
        
    def get_host_lease(self, address):
        """
        get the hostname, DUID, MAC and IAID to verify a lease to delete its address in the DNS
        """
        query = "SELECT DISTINCT hostname, duid, mac, iaid FROM leases WHERE address='%s'" % (address)
        answer = self.query(query)       
        if answer != None and len(answer)>0:
            if len(answer[0]) > 0:
                return answer[0]
            else:
                # calling method expects quartet of hostname, duid, mac, iad - get None if nothing there
                return (None, None, None, None)
        else:
            return (None, None, None, None)
        
    
    def release_lease(self, address):
        """
        release a lease via setting its active flag to False
        """
        query = "UPDATE %s SET active = 0, last_update = '%s' WHERE address = '%s'" % (self.table_leases, datetime.datetime.now(), address)
        answer = self.query(query)
        

    def check_lease(self, address, transaction_id):
        """
        check state of a lease for REBIND and RENEW messages
        """
        # attributes to identify host and lease
        query = "SELECT hostname, address, type, category, ia_type, class, preferred_until FROM %s WHERE active = 1\
                 AND address = '%s' AND mac = '%s' AND duid = '%s' AND iaid = '%s'" % \
                (self.table_leases, address,\
                 self.Transactions[transaction_id].MAC,\
                 self.Transactions[transaction_id].DUID,\
                 self.Transactions[transaction_id].IAID)
                
        answer = self.query(query)        
        return answer
        
    
    def release_free_leases(self, timestamp=datetime.datetime.now()):
        """
        release all invalid leases via setting their active flag to False
        """
        query = "UPDATE %s SET active = 0 WHERE valid_until < '%s'" % (self.table_leases, timestamp)
        answer = self.query(query)    
        return answer
    
    
    def remove_leases(self, category="random", timestamp=datetime.datetime.now()):
        """
        remove all leases of a certain category like random - they will grow the database 
        but be of no further use
        """
        query = "DELETE FROM %s WHERE active = 0 AND category = '%s' AND valid_until < '%s'" % (self.table_leases, category, timestamp)
        answer = self.query(query)    
        return answer
        
    
    def build_config_from_db(self, transaction_id):
        """
        get client config from db and build the appropriate config objects and indices
        """
        if self.Transactions[transaction_id].ClientConfigDB == None:
            query = "SELECT hostname, mac, duid, class, address, id FROM %s WHERE \
                    hostname = '%s' OR mac LIKE '%%%s%%' OR duid = '%s'" % \
                    (self.table_hosts,\
                     self.Transactions[transaction_id].FQDN,\
                     self.Transactions[transaction_id].MAC,\
                     self.Transactions[transaction_id].DUID)
            answer = self.query(query)      
            
            # add client config which seems to fit to transaction 
            self.Transactions[transaction_id].ClientConfigDB = ClientConfigDB()  
            
            # read al sections of config file
            # a section here is a host
            for host in answer:
                hostname, mac, duid, aclass, address, id = host
                self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname] = ClientConfig(hostname=hostname,\
                                                mac=mac,\
                                                duid=duid,\
                                                aclass=aclass,\
                                                address=address,\
                                                id=id)
                # in case of various MAC addresses split them...
                self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].MAC = ListifyOption(self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].MAC)

                # and put the host objects into index
                if self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].MAC:
                    for m in self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].MAC:
                        if not m in self.Transactions[transaction_id].ClientConfigDB.IndexMAC:
                            self.Transactions[transaction_id].ClientConfigDB.IndexMAC[m] = [self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname]]
                        else:
                            self.Transactions[transaction_id].ClientConfigDB.IndexMAC[m].append(self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname])
                            
                # add DUIDs to IndexDUID
                if not self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].DUID == "":
                    if not self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].DUID in self.Transactions[transaction_id].ClientConfigDB.IndexDUID:
                        self.Transactions[transaction_id].ClientConfigDB.IndexDUID[self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].DUID] = [self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname]]
                    else:
                        self.Transactions[transaction_id].ClientConfigDB.IndexDUID[self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname].DUID].append(self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname])
      
                                  
    def get_client_config_by_mac(self, transaction_id):
        """
        get host(s?) and its information belonging to that mac
        """       
        hosts = list()
        mac = self.Transactions[transaction_id].MAC
        if mac in self.Transactions[transaction_id].ClientConfigDB.IndexMAC:
            hosts.extend(self.Transactions[transaction_id].ClientConfigDB.IndexMAC[mac])
            return hosts
        else:
            return None
        
        
    def get_client_config_by_duid(self, transaction_id):
        """
        get host and its information belonging to that DUID
        """
        # get client config that most probably seems to fit
        #self.build_config_from_db(transaction_id)                
        
        hosts = list()
        duid = self.Transactions[transaction_id].DUID
        
        if duid in self.Transactions[transaction_id].ClientConfigDB.IndexDUID:
            """
            was is nu eigentlich wenn ein host die selbe duid noch hat aber ne neue mac addresse?
            """
            hosts.extend(self.Transactions[transaction_id].ClientConfigDB.IndexDUID[duid])
            return hosts
        else:
            return None
        
        
    def get_client_config_by_hostname(self, transaction_id):
        """
        get host and its information by hostname
        """
        # get client config that most probably seems to fit
        #self.build_config_from_db(transaction_id)
        
        hostname = self.Transactions[transaction_id].FQDN.split(".")[0]
        if hostname in self.Transactions[transaction_id].ClientConfigDB.Hosts:
            return [self.Transactions[transaction_id].ClientConfigDB.Hosts[hostname]]
        else:
            return None
        
        
    def get_client_config(self, hostname="", aclass="", duid="", address=[], mac=[], id=""):
        """
            give back ClientConfig object
        """
        return ClientConfig(hostname=hostname, aclass=aclass, duid=duid, address=address, mac=mac, id=id)
        

    def store_mac_llip(self, mac, link_local_ip):
        """
            store MAC-link-local-ip-mapping
        """
        query = "SELECT mac FROM macs_llips WHERE mac='%s'" % (mac)
        db_entry = self.query(query)
        # if known already update timestamp of MAC-link-local-ip-mapping
        if not db_entry:
            query = "INSERT INTO macs_llips (mac, link_local_ip, last_update) VALUES ('%s', '%s', '%s')" % \
                  (mac, link_local_ip, datetime.datetime.now())
            self.query(query)
        else:
            query = "UPDATE macs_llips SET link_local_ip = '%s', last_update = '%s' WHERE mac = '%s'" % (link_local_ip, datetime.datetime.now(), mac)
            self.query(query)
                    
                    
    def CollectMACsFromDB(self):
        """
            collect all known MACs and link local addresses from database at startup
            to reduce attempts to read neighbor cache
        """
        query = 'SELECT link_local_ip, mac FROM %s' % (self.table_macs_llips)
        answer = self.query(query)
        if answer:
            for m in answer:               
                try:
                    # m[0] is LLIP, m[1] is the matching MAC
                    self.CollectedMACs[m[0]] = m[1]
                except Exception, err:
                    #Log("ERROR: CollectMACsFromDB(): " + str(err))
                    print err
                    import traceback
                    traceback.print_exc(file=sys.stdout)
                    return None
                
        
    def DBQuery(self, query):
        """
        no not execute query on DB - dummy
        """
        # return empty tuple as dummy
        return ()


class SQLite(Store):
    """
    file-based SQLite database, might be an option for single installations
    """
    def __init__(self, cfg, queryqueue, answerqueue, Transactions, CollectedMACs, storage_type="volatile"):

        Store.__init__(self, cfg, queryqueue, answerqueue, Transactions, CollectedMACs)
        self.connection = None     
        
        try:
            self.DBConnect(storage_type)
        except:
            import traceback
            traceback.print_exc(file=sys.stdout)

        
    def DBConnect(self, storage_type="volatile"):
        """
        Initialize DB connection
        """

        import sqlite3
        
        try:
            if storage_type == "volatile": storage = self.cfg.STORE_SQLITE_VOLATILE
            if storage_type == "config": storage = self.cfg.STORE_SQLITE_CONFIG
            self.connection = sqlite3.connect(storage, check_same_thread = False)
            self.cursor = self.connection.cursor()
            self.connected = True                       
        except:
            import traceback
            traceback.print_exc(file=sys.stdout)
            return None
        
        
    def DBQuery(self, query):
        """
        execute query on DB
        """
        try:
            answer = self.cursor.execute(query)    
            # commit only if explicitly wanted
            if query.startswith("INSERT"):
                self.connection.commit()
            if query.startswith("UPDATE"):
                self.connection.commit()
            self.connected = True
        except:
            self.connected = False

        return answer.fetchall()
    
        
class Textfile(Store):
    """
    client config in text files
    """
    def __init__(self, cfg, queryqueue, answerqueue, Transactions, CollectedMACs):
        Store.__init__(self, cfg, queryqueue, answerqueue, Transactions, CollectedMACs)
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
        
        # read al sections of config file
        # a section here is a host
        for section in config.sections():
            self.Hosts[section] = ClientConfig()
            for item in config.items(section):
                self.Hosts[section].__setattr__(item[0].upper(), str(item[1]))
            
            # Test if host has ID
            if cfg.CLASSES.has_key(self.Hosts[section].CLASS):
                for a in cfg.CLASSES[self.Hosts[section].CLASS].ADDRESSES:
                    if cfg.ADDRESSES[a].CATEGORY == "id" and self.Hosts[section].ID == "":
                        ErrorExit("Textfile client configuration: No ID given for client '%s'" % (self.Hosts[section].HOSTNAME))
            else:
                ErrorExit("Textfile client configuration: Class '%s' of host '%s' is not defined" % (self.Hosts[section].CLASS, self.Hosts[section].HOSTNAME))
                
            if self.Hosts[section].ID != "":
                if self.Hosts[section].ID in self.IDs.keys():
                    ErrorExit("Textfile client configuration: ID '%s' of client '%s' is already used by '%s'." % (self.Hosts[section].ID, self.Hosts[section].HOSTNAME, self.IDs[self.Hosts[section].ID]))
                else:
                    self.IDs[self.Hosts[section].ID] = self.Hosts[section].HOSTNAME
                    
            # in case of various MAC addresses split them...
            self.Hosts[section].MAC = ListifyOption(self.Hosts[section].MAC)
            # and put the host objects into index
            if self.Hosts[section].MAC:
                for m in self.Hosts[section].MAC:
                    if not m in self.IndexMAC:
                        self.IndexMAC[m] = [self.Hosts[section]]
                    else:
                        self.IndexMAC[m].append(self.Hosts[section])
                        
            # add DUIDs to IndexDUID
            if not self.Hosts[section].DUID == "":
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
        mac = self.Transactions[transaction_id].MAC
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
        duid = self.Transactions[transaction_id].DUID
        if duid in self.IndexDUID:
            """
            was is nu eigentlich wenn ein host die selbe duid noch hat aber ne neue mac addresse?
            """
            hosts.extend(self.IndexDUID[duid])
            return hosts
        else:
            return None
        
        
    def get_client_config_by_hostname(self, transaction_id):
        """
        get host and its information by hostname
        """
        hostname = self.Transactions[transaction_id].FQDN.split(".")[0]
        if hostname in self.Hosts:
            return [self.Hosts[hostname]]
        else:
            return None
        
        
    def get_client_config(self, hostname="", aclass="", duid="", address=[], mac=[], id=""):
        """
        give back ClientConfig object
        """
        return ClientConfig( hostname=hostname, aclass=aclass, duid=duid, address=address, mac=mac, id=id)
            
        
class ClientConfig(object):
    """
    static client settings object to be stuffed into Hosts dict of Textfile store
    """
    def __init__(self, hostname="", aclass="default", duid="", address=None, mac=None, id=""):
        self.HOSTNAME = hostname
        # MACs
        self.MAC = mac
        # fixed addresses
        if address:
            addresses = ListifyOption(self.ADDRESS)
            for a in addresses:
                self.ADDRESS.append(DecompressIP6(a))
        else:
            self.ADDRESS = None
        self.CLASS = aclass
        self.ID = id
        self.DUID = duid
        

class ClientConfigDB(object):
    """
    class for storing client config snippet from DB - used in SQLite and MySQL Storage
    """
    def __init__(self):
        self.Hosts = dict()
        self.IndexMAC = dict()
        self.IndexDUID = dict()

    
class MySQL(Store):
    """
    MySQL database interface 
    for robustness see http://stackoverflow.com/questions/207981/how-to-enable-mysql-client-auto-re-connect-with-mysqldb
    """    
    
    def __init__(self, cfg, queryqueue, answerqueue, Transactions, CollectedMACs):
        Store.__init__(self, cfg, queryqueue, answerqueue, Transactions, CollectedMACs)

        self.connection = None

        try:
            self.DBConnect()
        except:
            import traceback
            traceback.print_exc(file=sys.stdout)
       
        
    def DBConnect(self):         
        import MySQLdb
   
        try:
            self.connection = MySQLdb.connect(host=self.cfg.STORE_MYSQL_HOST,\
                                              db=self.cfg.STORE_MYSQL_DB,\
                                              user=self.cfg.STORE_MYSQL_USER,\
                                              passwd=self.cfg.STORE_MYSQL_PASSWORD)
            self.cursor = self.connection.cursor()
            self.connected = True           
        except:
            import traceback
            traceback.print_exc(file=sys.stdout)
            return None
        
        
    def DBQuery(self, query):
        try:
            self.cursor.execute(query)
            self.connected = True
        except:            
            import traceback
            traceback.print_exc(file=sys.stdout)
            # try to reestablish database connection
            if not self.DBConnect():
                self.connected = False
                return None
            else:
                try:
                    self.cursor.execute(query)
                    self.connected = True
                except:
                    import traceback
                    traceback.print_exc(file=sys.stdout)
                    self.connected = False
                    return None
                
        result = self.cursor.fetchall()
        return result
    

