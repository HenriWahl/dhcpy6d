#!/usr/bin/env python
# encoding: utf8
"""
    DHCPy6d DHCPv6 Daemon
"""

import socket
import struct
import ctypes
import platform
import binascii
import datetime
import commands
import shlex
import sys
import hmac
import time
import threading
import Queue
import os.path
import re
import SocketServer
import traceback
import copy

from dhcpy6d.Helpers import *
from dhcpy6d.Constants import *
from dhcpy6d.Config import *
from dhcpy6d.Storage import *

# create and read config file
cfg = Config()

# RNDC Key for DNS updates from ISC Bind /etc/rndc.key
if cfg.DNS_UPDATE:
   import dns.update
   import dns.tsigkeyring
   import dns.query
   import dns.resolver
   import dns.reversename        
    
   Keyring = dns.tsigkeyring.from_text({cfg.DNS_RNDC_KEY : cfg.DNS_RNDC_SECRET})

   # resolver for DNS updates
   Resolver = dns.resolver.Resolver()
   Resolver.nameservers = [cfg.DNS_UPDATE_NAMESERVER]

# Logging
if cfg.LOG and cfg.LOG_FILE != "":
    Logfile = open(cfg.LOG_FILE, "a", 1)

# dictionary to store transactions - key is transaction ID, value a transaction object
Transactions = dict()

# collected MAC addresses from clients, mapping to link local IPs
CollectedMACs = dict()

# queues for queries
configqueryqueue = Queue.Queue()
configanswerqueue = Queue.Queue()
volatilequeryqueue = Queue.Queue()
volatileanswerqueue = Queue.Queue()

# queue for dns actualization
dnsqueue = Queue.Queue()

# save OS 
OS = platform.system()

# platform-dependant neighbor cache call
# every platform has its different output
# not used on Linux anymore, here a netlink socket is used.
NBC = { "Linux": { "call" : "/sbin/ip -6 neigh show",\
                         "dev"  : 2,\
                         "llip" : 0,\
                         "mac"  : 4 },\
        "OpenBSD": { "call" : "/usr/sbin/ndp -a -n",\
                         "dev"  : 2,\
                         "llip" : 0,\
                         "mac"  : 1}
            }

# libc access via ctypes, needed for interface handling
if OS == "Linux":
    libc_name = "libc.so.6"
elif OS == "OpenBSD":
    # libc_ver() returns version number of libc that is hardcoded in
    # libc file name
    libc_name = "libc.so." + platform.libc_ver()[1]
else:
    print "\n OS not yet supported. :-( \n"
    sys.exit(1)
# use ctypes for libc access
LIBC = ctypes.cdll.LoadLibrary(libc_name)

# index IF name > number, gets filled in UDPMulticastIPv6
IF_NAME = dict()
# index IF number > name
IF_NUMBER = dict()

# store 
# because of thread trouble there should not be too much db connections at once
# so we need to use the queryqueue way - subject to change
# source of configuration of hosts
# use client configuration only if needed
if cfg.STORE_CONFIG:
    if cfg.STORE_CONFIG == "file":
        configstore = Textfile(cfg, configqueryqueue, configanswerqueue, Transactions, CollectedMACs)
    if cfg.STORE_CONFIG == "mysql":
        configstore = MySQL(cfg, configqueryqueue, configanswerqueue, Transactions, CollectedMACs)
    if cfg.STORE_CONFIG == "sqlite":
        configstore = SQLite(cfg, configqueryqueue, configanswerqueue, Transactions, CollectedMACs, storage_type="config")
else:
    # dummy configstore if no client config is needed
    configstore = Store(cfg, configqueryqueue, configanswerqueue, Transactions, CollectedMACs)

# storage for changing data like leases, LLIPs, DUIDs etc.
if cfg.STORE_VOLATILE == "mysql":
    volatilestore = MySQL(cfg, volatilequeryqueue, volatileanswerqueue, Transactions, CollectedMACs)
if cfg.STORE_VOLATILE == "sqlite":
    volatilestore = SQLite(cfg, volatilequeryqueue, volatileanswerqueue, Transactions, CollectedMACs, storage_type="volatile")


def BuildClient(transaction_id):
    """
        builds client object of client config and transaction data
        checks if filters apply
        check if lease is still valid for RENEW and REBIND answers
        check if invalid addresses need to get deleted with lifetime 0
    """
    try:       
        # create client object
        client = Client()

        # configuration from client deriving from general config or filters - defaults to none
        client_config = None

        # list to collect filtered client information
        # if there are more than one entries that do not match the class is not uniquely identified
        filtered_class = dict()
        
        # check if there are identification attributes of any class - classes are sorted by filter types
        for f in cfg.FILTERS:
            # look into all classes and their filters
            for c in cfg.FILTERS[f]:
                # check further only if class applies to interface
                if Transactions[transaction_id].Interface in c.INTERFACE:
                    # MACs
                    if c.FILTER_MAC != "":
                        pattern = re.compile(c.FILTER_MAC)
                        # if mac filter fits client mac address add client config
                        if len(pattern.findall(Transactions[transaction_id].MAC)) > 0:
                            client_config = configstore.get_client_config(hostname=Transactions[transaction_id].Hostname,\
                                                                          mac=[Transactions[transaction_id].MAC],\
                                                                          duid=Transactions[transaction_id].DUID,\
                                                                          aclass=c.NAME)
                            # add classname to dictionary - if there are more than one entry classes do not match
                            # and thus are invalid
                            filtered_class[c.NAME] = c
                    # DUIDs
                    if c.FILTER_DUID != "":
                        pattern = re.compile(c.FILTER_DUID)
                        # if duid filter fits client duid address add client config
                        if len(pattern.findall(Transactions[transaction_id].DUID)) > 0:
                            client_config = configstore.get_client_config(hostname=Transactions[transaction_id].Hostname,\
                                                                          mac=[Transactions[transaction_id].MAC],\
                                                                          duid=Transactions[transaction_id].DUID,\
                                                                          aclass=c.NAME)
                            # see above
                            filtered_class[c.NAME] = c
                    # HOSTNAMEs
                    if c.FILTER_HOSTNAME != "":
                        pattern = re.compile(c.FILTER_HOSTNAME)
                        # if hostname filter fits client hostname address add client config
                        if len(pattern.findall(Transactions[transaction_id].Hostname)) > 0:
                            client_config = configstore.get_client_config(hostname=Transactions[transaction_id].Hostname,\
                                                                          mac=[Transactions[transaction_id].MAC],\
                                                                          duid=Transactions[transaction_id].DUID,\
                                                                          aclass=c.NAME)
                            # see above
                            filtered_class[c.NAME] = c

        # if there are more than 1 different classes matching for the client they are not valid         
        if len(filtered_class) != 1:
            client_config = None

        # if filters did not get a result try it the hard way        
        if client_config == None:
            # check all given identification criteria - if they all match each other the client is identified       
            id_attributes = list()

            # check every attribute which is required
            # depending on identificaton mode empty results are ignored or considered
            # finally all attributes are grouped in sets and for a correctly identified host
            # only one entry should appear at the end
            for i in cfg.IDENTIFICATION:
                if i == "mac":
                    # get all MACs for client from config
                    macs = configstore.get_client_config_by_mac(transaction_id)
                    if not macs == None:
                        macs = set(macs)
                        id_attributes.append("macs")
                    elif cfg.IDENTIFICATION_MODE == "match_all":
                        macs = set()
                        id_attributes.append("macs")
                if i == "duid":
                    duids = configstore.get_client_config_by_duid(transaction_id)
                    if not duids == None:
                        duids = set(duids)
                        id_attributes.append("duids")
                    elif cfg.IDENTIFICATION_MODE == "match_all":
                        duids = set()
                        id_attributes.append("duids")
                if i == "hostname":
                    hostnames = configstore.get_client_config_by_hostname(transaction_id)
                    if not hostnames == None:
                        hostnames = set(hostnames)
                        id_attributes.append("hostnames")
                    elif cfg.IDENTIFICATION_MODE == "match_all":
                        hostnames = set()
                        id_attributes.append("hostnames")

            # get intersection of all sets of identifying attributes - even the empty ones
            if len(id_attributes) > 0:
                client_config = set.intersection(eval("&".join(id_attributes)))
                if len(client_config) == 1:
                    # reuse client_config, grab it out of the set
                    client_config = client_config.pop()
                else:
                    # in case there is no client config we should maybe log this?
                    client_config = None
            else:
                client_config = None

        # If client gave some addresses for RENEW or REBIND consider them
        if Transactions[transaction_id].LastMessageReceivedType in (5, 6) and\
           not len(Transactions[transaction_id].Addresses) == 0:
            if not client_config == None:
                # give client hostname
                client.Hostname = client_config.HOSTNAME
                client.Class = client_config.CLASS
            for address in Transactions[transaction_id].Addresses:
                # check_lease returns hostname, address, type, category, ia_type, class, preferred_until of leased address
                answer = volatilestore.check_lease(address, transaction_id)
                if len(answer) > 0:
                    for item in answer:
                        a = dict(zip(("hostname", "address", "type", "category", "ia_type", "class", "preferred_until"), item))
                        # if lease exists but no configured client set class to default
                        if client_config == None:
                            client.Hostname = Transactions[transaction_id].Hostname
                            client.Class = "default_" + Transactions[transaction_id].Interface                                                        
                        # check if address type of lease still exists in configuration
                        # and if request interface matches that of class
                        if a["class"] in cfg.CLASSES and client.Class == a["class"] and\
                           Transactions[transaction_id].Interface in cfg.CLASSES[client.Class].INTERFACE:
                            # type of address must be defined in addresses for this class
                            # or fixed - in which case it is not class related
                            if a["type"] in cfg.CLASSES[a["class"]].ADDRESSES or a["type"] == "fixed":    

                                # flag for lease usage
                                use_lease = True

                                # test lease validity against address prototype pattern only if not fixed                               
                                if a["category"] != "fixed":
                                    # test if address matches pattern
                                    for i in range(len(address)):
                                        if address[i] != cfg.ADDRESSES[a["type"]].PROTOTYPE[i] and \
                                           cfg.ADDRESSES[a["type"]].PROTOTYPE[i] != "X":
                                            use_lease = False
                                            break
                                elif not address in client_config.ADDRESS:
                                    use_lease = False

                                # only use lease if it still matches prototype
                                if use_lease == True:
                                    # when category is range, test if it still applies
                                    if a["category"] == "range":
                                        # borrowed from ParseAddressPattern to find out if lease is still in a meanwhile maybe changed range                                                
                                        frange, trange = cfg.ADDRESSES[a["type"]].RANGE.split("-")   

                                        # correct possible misconfiguration
                                        if len(frange)<4:
                                            frange ="0"*(4-len(frange)) + frange
                                        if len(trange)<4:
                                            trange ="0"*(4-len(trange)) + trange
                                        if frange > trange:
                                            frange, trange = trange, frange
                                        # if lease is still inside range boundaries use it
                                        if frange <= address[28:].lower() < trange:                                           
                                            # build IA partly of leases db, partly of config db
                                            ia = Address(address=ColonifyIP6(a["address"]),\
                                                         atype=a["type"],\
                                                         preferred_lifetime=cfg.ADDRESSES[a["type"]].PREFERRED_LIFETIME,\
                                                         valid_lifetime=cfg.ADDRESSES[a["type"]].VALID_LIFETIME,\
                                                         category=a["category"],\
                                                         ia_type=a["ia_type"],\
                                                         aclass=a["class"])
                                            client.Addresses.append(ia)                                       
                                    else: 
                                        # build IA partly of leases db, partly of config db
                                        ia = Address(address=ColonifyIP6(a["address"]),\
                                                     atype=a["type"],\
                                                     preferred_lifetime=cfg.ADDRESSES[a["type"]].PREFERRED_LIFETIME,\
                                                     valid_lifetime=cfg.ADDRESSES[a["type"]].VALID_LIFETIME,\
                                                     category=a["category"],\
                                                     ia_type=a["ia_type"],\
                                                     aclass=a["class"])
                                        client.Addresses.append(ia)
        
                    # look for addresses in transaction that are invalid and add them
                    # to client addresses with flag invalid and a RFC-compliant lifetime of 0
                    for a in set(Transactions[transaction_id].Addresses).difference(map(lambda x: DecompressIP6(x.ADDRESS), client.Addresses)):
                        client.Addresses.append(Address(address=ColonifyIP6(a), valid=False,\
                                                        preferred_lifetime=0,\
                                                        valid_lifetime=0))
                         
                    return client

        # build IA addresses from config - fixed ones and dynamic
        if client_config != None:    
            # give client hostname + class
            client.Hostname = client_config.HOSTNAME
            client.Class = client_config.CLASS

            # continue only if request interface matches class interfaces
            if Transactions[transaction_id].Interface in cfg.CLASSES[client.Class].INTERFACE:
                # if fixed addresses are given build them
                if not client_config.ADDRESS == None:
                    for address in client_config.ADDRESS:
                        if len(address) > 0:
                            # fixed addresses are assumed to be non-temporary
                            # 
                            # todo: lifetime of address should be set by config too                       
                            #
                            ia = Address(address=address, ia_type="na",\
                                         preferred_lifetime=cfg.PREFERRED_LIFETIME,\
                                         valid_lifetime=cfg.VALID_LIFETIME, category="fixed",\
                                         aclass="fixed", atype="fixed")
    
                            client.Addresses.append(ia)     
    
                if not client_config.CLASS == "":
                    # add all addresses which belong to that class
                    for address in cfg.CLASSES[client_config.CLASS].ADDRESSES:  
                        a = ParseAddressPattern(cfg.ADDRESSES[address], client_config, transaction_id)
                        # Address class is borrowed from Config.py
                        # in case range has been exceeded a will be None
                        if not a == None:
                            ia = Address(address=a, ia_type=cfg.ADDRESSES[address].IA_TYPE,\
                                         preferred_lifetime=cfg.ADDRESSES[address].PREFERRED_LIFETIME,\
                                         valid_lifetime=cfg.ADDRESSES[address].VALID_LIFETIME,\
                                         category=cfg.ADDRESSES[address].CATEGORY,\
                                         aclass=cfg.ADDRESSES[address].CLASS,\
                                         atype=cfg.ADDRESSES[address].TYPE,\
                                         dns_update=cfg.ADDRESSES[address].DNS_UPDATE,\
                                         dns_zone=cfg.ADDRESSES[address].DNS_ZONE,\
                                         dns_rev_zone=cfg.ADDRESSES[address].DNS_REV_ZONE,\
                                         dns_ttl=cfg.ADDRESSES[address].DNS_TTL)
                            client.Addresses.append(ia)
                            
                if client_config.ADDRESS == client_config.CLASS == "":
                    # use default class if no class or address is given
                    for address in cfg.CLASS["default_" + Transactions[transaction_id].Interface].ADDRESSES:
                        client.Class = "default_" + Transactions[transaction_id].Interface
                        a = ParseAddressPattern(cfg.ADDRESSES[address], client_config, transaction_id)
                        # Address class is borrowed from Config.py
                        ia = Address(address=a, ia_type=cfg.ADDRESSES[address].IA_TYPE,\
                                     preferred_lifetime=cfg.ADDRESSES[address].PREFERRED_LIFETIME,\
                                     valid_lifetime=cfg.ADDRESSES[address].VALID_LIFETIME,\
                                     category=cfg.ADDRESSES[address].CATEGORY,\
                                     aclass=cfg.ADDRESSES[address].CLASS,\
                                     atype=cfg.ADDRESSES[address].TYPE,\
                                     dns_update=cfg.ADDRESSES[address].DNS_UPDATE,\
                                     dns_zone=cfg.ADDRESSES[address].DNS_ZONE,\
                                     dns_rev_zone=cfg.ADDRESSES[address].DNS_REV_ZONE,\
                                     dns_ttl=cfg.ADDRESSES[address].DNS_TTL)
                        client.Addresses.append(ia)           
        else:
            # use default class if host is unknown
            client.Hostname = Transactions[transaction_id].Hostname
            client.Class = "default_" + Transactions[transaction_id].Interface            
            for address in cfg.CLASSES["default_" + Transactions[transaction_id].Interface].ADDRESSES:  
                a = ParseAddressPattern(cfg.ADDRESSES[address], client, transaction_id)
                # Address class is borrowed from Config.py
                ia = Address(address=a, ia_type=cfg.ADDRESSES[address].IA_TYPE,\
                             preferred_lifetime=cfg.ADDRESSES[address].PREFERRED_LIFETIME,\
                             valid_lifetime=cfg.ADDRESSES[address].VALID_LIFETIME,\
                             category=cfg.ADDRESSES[address].CATEGORY,\
                             aclass=cfg.ADDRESSES[address].CLASS,\
                             atype=cfg.ADDRESSES[address].TYPE,\
                             dns_update=cfg.ADDRESSES[address].DNS_UPDATE,\
                             dns_zone=cfg.ADDRESSES[address].DNS_ZONE,\
                             dns_rev_zone=cfg.ADDRESSES[address].DNS_REV_ZONE,\
                             dns_ttl=cfg.ADDRESSES[address].DNS_TTL)
                client.Addresses.append(ia)

        return client

    except Exception,err:
        Log("ERROR: BuildClient(): " + str(err))
        print err
        import traceback
        traceback.print_exc(file=sys.stdout)
        return None


def CollectMACs():
    """
        collect MAC address from clients to link local addresses with MACs
        if a client has a new MAC the LLIP changes - with privacy extension enabled anyway
        calls local ip command to get neighbor cache - any more sophisticated idea is welcome!
    """
    try:
        # Linux can use kernel neighbor cache
        if OS == "Linux":
            for host in GetNeighborCacheLinux(cfg, IF_NAME, IF_NUMBER, LIBC):
                if host["interface"] in cfg.INTERFACE:
                    if not CollectedMACs.has_key(host["llip"]) and host["llip"].lower().startswith("fe80:"):
                        CollectedMACs[host["llip"]] = host["mac"]
                        Log("Collected MAC: %s for LinkLocalIP: %s" % (host["mac"], host["llip"]))
                        volatilestore.store_mac_llip(host["mac"], host["llip"])
        else:
            # subject to change - other distros might have other paths - might become a task
            # for a setup routine to find appropriate paths 
            for host in commands.getoutput(NBC[OS]["call"]).splitlines():
                # get fragments of output line
                f = shlex.split(host)
                if f[NBC[OS]["dev"]] in cfg.INTERFACE:
                    # get rid of %interface 
                    f[NBC[OS]["llip"]] = ColonifyIP6(DecompressIP6(f[NBC[OS]["llip"]].split("%")[0]))
                    # correct maybe shortenend MAC
                    f[NBC[OS]["mac"]] = CorrectMAC(f[NBC[OS]["mac"]]) 
                    # put non yet existing LLIPs into dictionary - if they have MACs
                    if not CollectedMACs.has_key(f[NBC[OS]["llip"]]) and f[NBC[OS]["llip"]].lower().startswith("fe80:")\
                       and ":" in f[NBC[OS]["mac"]]:
                        CollectedMACs[f[NBC[OS]["llip"]]] = f[NBC[OS]["mac"]]
                        Log("Collected MAC: %s for LinkLocalIP: %s" % (f[NBC[OS]["mac"]], f[NBC[OS]["llip"]]))
                        volatilestore.store_mac_llip(f[NBC[OS]["mac"]], f[NBC[OS]["llip"]])
            

                    
    except Exception,err:
        Log("ERROR: CollectMacs(): " + str(err))
        print err
        import traceback
        traceback.print_exc(file=sys.stdout)


def DNSUpdate(transaction_id, action="update"):
    """
    update DNS entries on specified nameserver
    at the moment this only works with Bind
    uses all addresses of client if they want to be dynamically updated
    
    regarding RFC 4704 5. there are 3 kinds of client behaviour for N O S:
    - client wants to update DNS itself -> sends 0 0 0
    - client wants server to update DNS -> sends 0 0 1
    - client wants no server DNS update -> sends 1 0 0     
    """
    # if allowed use client supplied hostname, otherwise that from config
    if cfg.DNS_USE_CLIENT_HOSTNAME and not cfg.DNS_IGNORE_CLIENT:
        hostname = Transactions[transaction_id].Hostname
    else:
        hostname = Transactions[transaction_id].Client.Hostname
    
    # if address should be updated in DNS update it
    for a in Transactions[transaction_id].Client.Addresses:
        if a.DNS_UPDATE and hostname != "" and a.VALID == True:
            if cfg.DNS_IGNORE_CLIENT or Transactions[transaction_id].DNS_S == 1:
                # put query into DNS query queue
                dnsqueue.put((hostname, a, action))
            
            
def DNSDelete(transaction_id, address="", action="release"):
    """
    delete DNS entries on specified nameserver
    at the moment this only works with ISC Bind
    """    
    hostname, duid, mac, iaid = volatilestore.get_host_lease(address)
    
    # if address should be updated in DNS update it
    # local flag to check if address should be deleted from DNS
    delete = False

    for a in cfg.ADDRESSES.values():
        # if there is any address type which prototype matches use its DNS ZONE
        if a.matches_prototype(address):  
            # kind of RCF-compliant security measure - check if hostname and DUID from transaction fits them of store
            if duid == Transactions[transaction_id].DUID and\
               iaid == Transactions[transaction_id].IAID:
                delete = True
                # also check MAC address if MAC counts in general - not RFCish
                if "mac" in cfg.IDENTIFICATION:
                    if not mac == Transactions[transaction_id].MAC:
                        delete = False
            
            if hostname != "" and delete == True:
                # use address from address types as template for the real
                # address to be deleted from DNS
                dns_address = copy.copy(a)
                dns_address.ADDRESS = ColonifyIP6(address)
                # put query into DNS query queue
                dnsqueue.put((hostname, dns_address, action))   
            # enough    
            break
        

class DNSQueryThread(threading.Thread):
    """
    thread for updating DNS entries of valid leases 
    """

    def __init__(self, dnsqueue):
        threading.Thread.__init__(self, name="DNSQuery")
        self.setDaemon(1)
        self.dnsqueue=dnsqueue

    def run(self):
        # wait for new queries in queue until the end of the world
        while True:
            hostname, a, action = self.dnsqueue.get()
            try:
                # update AAAA record, delete old entry first
                update = dns.update.Update(a.DNS_ZONE, keyring=Keyring)
                update.delete(hostname, "AAAA")
                # if DNS should be updated do it - not the case if IP is released
                if action == "update":
                    update.add(hostname, a.DNS_TTL, "AAAA", a.ADDRESS)
                dns.query.tcp(update, cfg.DNS_UPDATE_NAMESERVER)

                # the reverse record will be first checked if it points
                # to the current hostname, if not, it will be deleted first
                update_rev = dns.update.Update(a.DNS_REV_ZONE, keyring=Keyring)
                try:
                    answer = Resolver.query(dns.reversename.from_address(a.ADDRESS), "PTR")
                    for rdata in answer:
                        hostname_ns = str(rdata).split(".")[0]
                        # if ip address is related to another host delete this one
                        if hostname_ns != hostname:
                            #update_rev.delete(dns.reversename.from_address(a.ADDRESS), "PTR", hostname_ns + "." + a.DNS_ZONE + ".")  
                            update_rev.delete(dns.reversename.from_address(a.ADDRESS), "PTR", hostname_ns + "." + a.DNS_ZONE + ".")  

                except dns.resolver.NXDOMAIN:
                    pass
                # if DNS should be updated do it - not the case if IP is released
                if action == "update":
                    update_rev.add(dns.reversename.from_address(a.ADDRESS), a.DNS_TTL, "PTR", hostname + "." + a.DNS_ZONE + ".")  
                elif action == "release":
                    update_rev.delete(dns.reversename.from_address(a.ADDRESS), "PTR")  
                dns.query.tcp(update_rev, cfg.DNS_UPDATE_NAMESERVER)
            except Exception,err:
                Log("ERROR: DNSUPDATE: " + str(err))
                print err
                import traceback
                traceback.print_exc(file=sys.stdout)            
            

def ParseAddressPattern(address, client_config, transaction_id):
    """
    parse address pattern and replace variables with current values
    """
    # parse all pattern parts
    a = address.PATTERN

    # check different client address categories - to be extended!
    if address.CATEGORY == "mac":
        macraw = "".join(Transactions[transaction_id].MAC.split(":"))
        a = a.replace("$mac$", ":".join((macraw[0:4], macraw[4:8], macraw[8:12])))
    elif address.CATEGORY == "id":
        # if there is an ID build address
        if str(client_config.ID) <> "":
            a = a.replace("$id$", str(client_config.ID))
        else:
            return None
    elif address.CATEGORY == "random":
        ra = str(hex(random.getrandbits(64)))[2:][:-1]
        ra = ":".join((ra[0:4], ra[4:8], ra[8:12], ra[12:16]))
        # subject to change....
        a = a.replace("$random64$", ra)
    elif address.CATEGORY == "range":
        frange, trange = address.RANGE.split("-")       
        if len(frange)<4:
            frange ="0"*(4-len(frange)) + frange
        if len(trange)<4:
            trange ="0"*(4-len(trange)) + trange
        if frange > trange:
            frange, trange = trange, frange

        # expecting range-range at the last octet, "prefix" means the first seven octets here 
        # - is just shorter than the_first_seven_octets
        prefix = "".join(DecompressIP6(a.replace("$range$", "0000"))[:28])
        # first look for highest inactive (free) lease
        lease = volatilestore.get_lease(active=0, prefix=prefix, frange=frange, trange=trange)
        # gotten lease has to be in range - important after changed range boundaries 
        if not lease == None and frange <= lease[28:].lower() < trange:
            a = ":".join((lease[0:4], lease[4:8], lease[8:12], lease[12:16],\
                          lease[16:20], lease[20:24], lease[24:28], lease[28:32]))
        else:
            lease = volatilestore.get_lease(active=1, prefix=prefix, frange=frange, trange=trange)
            # second search highest active lease  
            if not lease == None and frange <= lease[28:].lower() < trange:     
                # Here logging is very important if range has been exceeded
                if lease[28:].lower() >= trange:
                    #
                    # log log log
                    #
                    return None
                else:
                    a = a.replace("$range$", str(hex(int(lease[28:], 16) + 1)).split("x")[1])
            else:           
                # this will be done only once - the first time if there is no other lease yet
                # so it is safe to start from frange
                a = a.replace("$range$", frange)
    return a


def Log(logstring):
    """
       log into a logfile or console
    """
    if cfg.LOG:
        if cfg.LOG_FILE != "":
            Logfile.write(str(datetime.datetime.now()) + " - " + logstring + "\n")
        if cfg.LOG_CONSOLE:
            print str(datetime.datetime.now()) + " - " + logstring + "\n"


class TidyUpThread(threading.Thread):
    """
        clean leases and transactions if obsolete
    """    
    def __init__(self):
        threading.Thread.__init__(self, name="TidyUp")
        self.setDaemon(1) 

    def run(self):
        try:
            #get and delete invalid leases
            while True:
                # nach abgeschlossener Transaktion kann man ruhig aufraeumen, alles was aelter als 1 Minute ist
                # fliegt raus
                # die Verzoegerung ist vermutlich wegen des Threadings besser, damit sich nicht u.U. Threads
                # gegenseitig die Daten loeschen
                now = datetime.datetime.now()
                timedelta = datetime.timedelta(seconds=10)
                for t in Transactions.copy().keys():
                    try:
                        if now > Transactions[t].Timestamp + timedelta:
                            Transactions.pop(Transactions[t].ID)

                    except Exception, err:
                        print "TransactionID %s has already been deleted" % (str(err))
                        Log("ERROR: TidyUp: TransactionID %s has already been deleted" % (str(err)))    
                        import traceback
                        traceback.print_exc(file=sys.stdout)

                # remove leases which might not be recycled like random addresses for example
                volatilestore.remove_leases(category="random", timestamp=datetime.datetime.now())

                # set leases free whose valid lifetime is over
                volatilestore.release_free_leases(datetime.datetime.now())

                # cleaning once per minute should be enough
                time.sleep(60)

        except:
            import traceback
            traceback.print_exc(file=sys.stdout)


class Client(object):
    """
        client objected, generated from configuration database or on the fly
    """
    def __init__(self):
        # Addresses, depending on class or fixed addresses
        self.Addresses = list()
        # DUID
        self.DUID = ""
        # current link-local IP
        self.LLIP = ""
        # Hostname
        self.Hostname = ""
        # Class/role of client
        self.Class = ""
        # MAC
        self.MAC = ""
        # timestamp of last update
        self.LastUpdate = ""


    def _getOptionsString(self):
        """
            all attributes in a string for logging
        """
        optionsstring = ""
        # put own attributes into a string
        options = self.__dict__.keys()
        options.sort()
        for o in options:
            # ignore some attributes
            if not o in ["OptionsRaw", "Client", "Timestamp", "DUIDLLAddress", "IAT1", "IAT2", "IP6_old", "LLIP_old"] and not str(self.__dict__[o]) == "":
                if not o == "Addresses":
                    option = o + ": " + str(self.__dict__[o]) + " "
                    optionsstring += option
                else:
                    option = "Addresses:"
                    for a in self.__dict__[o]:
                        option += " " + a.ADDRESS
                    optionsstring += option + " "  

        return optionsstring


class Transaction(object):
    """
        all data of one transaction, to be collected in Transactions
    """
    def __init__(self, transaction_id, client_llip, interface, message_type, options):
        # Transaction ID
        self.ID = transaction_id
        # Link Local IP of client
        self.ClientLLIP = client_llip
        # Interface the request came in
        self.Interface = interface
        # MAC address
        self.MAC = ""
        # last message for following the protocol
        self.LastMessageReceivedType = message_type
        # dictionary for options
        self.OptionsRaw = options
        # default dummy OptionsRequest
        self.OptionsRequest = list()
        # timestamp to manage/clean transactions
        self.Timestamp = datetime.datetime.now()
        # dummy hostname
        self.FQDN = ""
        self.Hostname = ""
        # DNS Options for option 39
        self.DNS_N = 0
        self.DNS_O = 0
        self.DNS_S = 0
        # dummy IAID
        self.IAID = "00000000"
        # dummy IAT1
        self.IAT1 = cfg.PREFERRED_LIFETIME        
        # dummy IAT2
        self.IAT2 = cfg.VALID_LIFETIME
        # Addresses given by client, for example for RENEW or RELEASE requests
        self.Addresses = list()
        # might be used against clients that are running wild
        self.Counter = 0
        # temporary storage for client configuration from DB config 
        # - only used if config comes from DB
        self.ClientConfigDB = None
        # client config from config store
        self.Client = None
        # Vendor Class Option
        self.VendorClassEN = None
        self.VendorClassData = ""
        # Rapid Commit flag
        self.RapidCommit = False

        # DUID of client
        # 1 Client Identifier Option
        if options.has_key(1):
            duid_client = options[1]
            duid_type = int(options[1][0:4], 16)
            duid_hardware_type = int(options[1][4:8], 16)
            # dummy LL address
            duid_link_layer_address = "00:00:00:00:00:00"
            # DUID-LLT
            if duid_type == 1:
                duid_time = int(options[1][8:16], 16)
                # temp link layer address = lla
                lla = options[1][16:]
                duid_link_layer_address = ":".join((lla[0:2], lla[2:4], lla[4:6], lla[6:8], lla[8:10], lla[10:12]))

            # DUID-EN
            elif duid_type == 2:
                # nothing to to with enterprise DUID at the moment
                pass
            # DUID-LL
            elif duid_type == 3:
                duid_time = int(options[1][8:16], 16)
                # temp link layer address = lla
                lla = options[1][8:]
                duid_link_layer_address = ":".join((lla[0:2], lla[2:4], lla[4:6], lla[6:8], lla[8:10], lla[10:12]))

            # whatever for... it is even forbidden to use the DUIDLLAddress....
            self.DUID = duid_client
            self.DUIDType = duid_type
            self.DUIDLLAddress = duid_link_layer_address

        # Identity Association for Non-temporary Addresses
        # 3 Identity Association for Non-temporary Address Option
        if options.has_key(3):
            for payload in options[3]:
                ia_id = payload[0:8]
                ia_t1 = int(payload[8:16], 16)
                ia_t2 = int(payload[16:24], 16)
                self.IAID = ia_id
                self.IAT1 = ia_t1
                self.IAT2 = ia_t2
                
                # addresses given by client if any
                for a in range(len(payload[32:])/44):
                    address = payload[32:][(a*56):(a*56)+32]
                    # in case an address is asked for twice by one host ignore the twin
                    if not address in self.Addresses:
                        self.Addresses.append(address)

        # Options Requested
        # 6 Option Request Option
        if options.has_key(6):
            options_request = list()
            opts = options[6][:]
            while len(opts) > 0:
                options_request.append(int(opts[0:4], 16))
                opts = opts[4:]
            self.OptionsRequest = options_request         

        # 14 Rapid Commit flag
        if options.has_key(14):
            self.RapidCommit = True

        # 16 Vendor Class Option
        if options.has_key(16):
            self.VendorClassEN = int(options[16][0:8], 16)
            self.VendorClassData = binascii.unhexlify(options[16][12:])

        # FQDN
        # 39 FQDN Option
        if options.has_key(39):
            bits = ("%4s" % (str(bin(int(options[39][1:2]))).strip("0b"))).replace(" ", "0")
            self.DNS_N = int(bits[1])
            self.DNS_O = int(bits[2])
            self.DNS_S = int(bits[3])    
            name = ConvertBinary2DNS(options[39][2:])
            # only hostname needed
            self.FQDN = name.lower()
            self.Hostname = name.split(".")[0].lower()


    def _getOptionsString(self):
        """
            get all options in one string for debugging
        """
        optionsstring = ""
        # put own attributes into a string
        options = self.__dict__.keys()
        options.sort()
        for o in options:
            # ignore some attributes 
            if not o in ["OptionsRaw", "Client", "Timestamp", "DUIDLLAddress", "IAT1", "IAT2", "ClientConfigDB"] and \
               not self.__dict__[o] in [None, False, "", []]:
                option = o + ": " + str(self.__dict__[o]) + " "
                optionsstring += option
        return optionsstring


class UDPMulticastIPv6(SocketServer.UnixDatagramServer):    
    """
        modify server_bind to work with multicast
        add DHCPv6 multicast group ff02::1:2
    """
    def server_bind(self):
        """
            multicast & python: http://code.activestate.com/recipes/442490/
        """
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # multicast parameters
        # hop is one because it is all about the same subnet
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
        # looks like there is no other way to find interfaces than via libc
        for i in cfg.INTERFACE:
            IF_NAME[i] = LIBC.if_nametoindex(i)
            IF_NUMBER[IF_NAME[i]] = i
            if_number = struct.pack("I", LIBC.if_nametoindex(i))
            mgroup = socket.inet_pton(socket.AF_INET6, cfg.MCAST) + if_number

            # join multicast group
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mgroup)

        # bind socket to server address
        self.socket.bind(self.server_address)

        # some more requests?
        self.request_queue_size = 100


class Handler(SocketServer.DatagramRequestHandler):
    """
        manage all incoming datagrams
    """

    def handle(self):
        """
            request handling happens here
        """
        # empty dummy response
        self.response = ""
        try:
            # convert raw message into ascii-bytes
            bytes = binascii.b2a_hex(self.request[0])

            # clean client IP address - might come in short notation, which
            # should be extended
            client_llip, interface = self.client_address[0].split("%")
            client_llip = ColonifyIP6(DecompressIP6(client_llip))

            # bad or too short message is thrown away
            if not len(bytes) > 8:
                pass
            else:
                message_type = int(bytes[0:2], 16)
                transaction_id = bytes[2:8]
                bytes_options = bytes[8:]
                options = {}
                while len(bytes_options) > 0:
                    # option type and length are 2 bytes each
                    option = int(bytes_options[0:4], 16)
                    length = int(bytes_options[4:8], 16)
                    # *2 because 2 bytes make 1 char
                    value = bytes_options[8:8 + length*2]
                    # Microsoft behaves a little bit different than the other
                    # clients - in RENEW and REBIND request multiple addresses of an
                    # IAID are not requested all in one option type 3 but
                    # come in several options of type 3 what leads to some confusion
                    if option != 3:
                        options[option] = value
                    else:
                        if options.has_key(3):
                            options[3].append(value)
                        else:
                            options[3] = list()
                            options[3].append(value)

                    # cut off bytes worked on
                    bytes_options = bytes_options[8 + length*2:]

                # only valid messages will be processed 
                if message_type in MESSAGE_TYPES:
                    # 2. Erstelle Transaction Object wenn noch nicht vorhanden
                    if not Transactions.has_key(transaction_id):
                        Transactions[transaction_id] = Transaction(transaction_id, client_llip, interface, message_type, options)
                        # add client MAC address to transaction object
                        if CollectedMACs.has_key(Transactions[transaction_id].ClientLLIP):
                            Transactions[transaction_id].MAC = CollectedMACs[Transactions[transaction_id].ClientLLIP]
                    else:
                        Transactions[transaction_id].Timestamp = datetime.datetime.now()
                        Transactions[transaction_id].LastMessageReceivedType = message_type

                    # logging
                    Log("%s: TransactionID: %s %s" % (MESSAGE_TYPES[message_type], transaction_id, Transactions[transaction_id]._getOptionsString()))

                    # 3. answer requests
                    # check if client sent a valid DUID (alphanumeric)
                    if Transactions[transaction_id].DUID.isalnum():
                    # client will get answer if its LLIP/MAC is known MAC
                        if not Transactions[transaction_id].ClientLLIP in CollectedMACs:
                            # if not known senf status code option failure to get
                            # LLIP/MAC mapping from neighbor cache
                            self.build_response(7, transaction_id, [13], 0)
                            # complete MAC collection
                            CollectMACs()
                            # try to add client MAC address to transaction object
                            try:
                                Transactions[transaction_id].MAC = CollectedMACs[Transactions[transaction_id].ClientLLIP]
                            except:
                                # MAC not yet found :-(
                                Log("%s: TransactionID: %s %s" % (MESSAGE_TYPES[message_type], transaction_id, "MAC address for LinkLocalIP %s unknown." % (Transactions[transaction_id].ClientLLIP)))
                        else:
                            # ADVERTISE
                            # if last request was a SOLICIT send an ADVERTISE (type 2) back
                            if Transactions[transaction_id].LastMessageReceivedType == 1 \
                               and Transactions[transaction_id].RapidCommit == False:
                                # preference option (7) is for free
                                self.build_response(2, transaction_id, [3] + [7] + Transactions[transaction_id].OptionsRequest)

                            # REQUEST
                            # if last request was a REQUEST (type 3) send a REPLY (type 7) back
                            elif Transactions[transaction_id].LastMessageReceivedType == 3 or \
                                 (Transactions[transaction_id].LastMessageReceivedType == 1 and \
                                  Transactions[transaction_id].RapidCommit == True):
                                # preference option (7) is for free
                                # if RapidCommit was set give it back
                                if not Transactions[transaction_id].RapidCommit:
                                    self.build_response(7, transaction_id, [3] + [7] + Transactions[transaction_id].OptionsRequest)
                                else:
                                    self.build_response(7, transaction_id, [3] + [7] + [14] + Transactions[transaction_id].OptionsRequest)
                                # store leases for addresses
                                volatilestore.store_lease(transaction_id)
                                if cfg.DNS_UPDATE:
                                    DNSUpdate(transaction_id)

                            # CONFIRM
                            # if last request was a CONFIRM (4) send a REPLY (type 7) back 
                            elif Transactions[transaction_id].LastMessageReceivedType == 4:
                                # Windows seems to have a problem with CONFIRM messages
                                # Microsoft Enterprise Number EN is 311
                                #if Transactions[transaction_id].VendorClassEN == 311 and\
                                #   Transactions[transaction_id].VendorClassData.startswith("MSFT"):
                                #    # try with error to force new solicit
                                #    #self.build_response(7, transaction_id, [13], 1)
                                #    self.build_response(7, transaction_id, [13], 4)
                                #
                                #else:
                                #    # the others need to be tested...
                                #    ###self.build_response(7, transaction_id, [3] + Transactions[transaction_id].OptionsRequest)
                                #    # store leases for addresses
                                #    ###volatilestore.store_lease(transaction_id)
                                #    self.build_response(7, transaction_id, [13], 4)
                                #    pass
                                # the RFC 3315 is a little bit confusing regarding CONFIRM
                                # messages so it won't hurt to simply let the client
                                # solicit addresses again via answering "NotOnLink"
                                self.build_response(7, transaction_id, [13], 4)

                            # RENEW
                            # if last request was a RENEW (type 5) send a REPLY (type 7) back  
                            elif Transactions[transaction_id].LastMessageReceivedType == 5:
                                self.build_response(7, transaction_id, [3] + [7] + Transactions[transaction_id].OptionsRequest)
                                # store leases for addresses
                                volatilestore.store_lease(transaction_id)
                                if cfg.DNS_UPDATE:
                                    DNSUpdate(transaction_id)

                            # REBIND
                            # if last request was a REBIND (type 6) send a REPLY (type 7) back  
                            elif Transactions[transaction_id].LastMessageReceivedType == 6:
                                self.build_response(7, transaction_id, [3] + [7] + Transactions[transaction_id].OptionsRequest)
                                # store leases for addresses
                                volatilestore.store_lease(transaction_id)

                            # RELEASE
                            # if last request was a RELEASE (type 8) sende a REPLY (type 7) back  
                            elif Transactions[transaction_id].LastMessageReceivedType == 8:                            
                                if cfg.DNS_UPDATE:
                                    # build client to be able to delete it from DNS
                                    Transactions[transaction_id].Client = BuildClient(transaction_id)
                                    for a in Transactions[transaction_id].Addresses:
                                        DNSDelete(transaction_id, address=a, action="release")
                                for a in Transactions[transaction_id].Addresses:
                                    # free lease
                                    volatilestore.release_lease(a)   
                                # send status code option (type 13) with success (type 0) 
                                self.build_response(7, transaction_id, [13], 0)                      

                            # DECLINE
                            # if last request was a DECLINE (type 9) send a REPLY (type 7) back  
                            elif Transactions[transaction_id].LastMessageReceivedType == 9:
                                # maybe has to be refined - now only a status code "NoBinding" is answered
                                self.build_response(7, transaction_id, [13], 3)

                            # INFORMATION-REQUEST    
                            # wenn letzter Request ein INFORMATION-REQUEST (type 11) war sende ein REPLY (type 7) zurueck  
                            elif Transactions[transaction_id].LastMessageReceivedType == 11:
                                self.build_response(7, transaction_id, Transactions[transaction_id].OptionsRequest)

                            # general error - statuscode 1 "Failure"
                            else:
                                # sende Status Code Option (type 13) mit Failure (type 1) 
                                self.build_response(7, transaction_id, [13], 1)

                        # in case there is no address gibe back failure message
                        if Transactions[transaction_id].Client <> None and len(Transactions[transaction_id].Client.Addresses) == 0:
                            # give back error code 2 "No addresses available"
                            self.build_response(7, transaction_id, [13], 2)

                    # count requests of transaction
                    # if there will be too much something went wrong
                    # may be evaluated to reset the whole transaction
                    Transactions[transaction_id].Counter += 1

        except Exception,err:
            Log("ERROR: handle(): " + str(err))
            print err
            import traceback
            traceback.print_exc(file=sys.stdout)   
            return None


    def build_response(self, response_type, transaction_id, options_request, status=0):
        """
            creates answer and puts it into self.response
            arguments:
                response_type - mostly 2 or 7
                transaction_id
                option_request 
                status -mostly 0 (OK)
            response will be sent by self.finish()
        """
        try:           
            # Header
            # response type + transaction id
            response_ascii = "%02x" % (response_type)
            response_ascii += transaction_id

            # diese Optionen sind immer zu gebrauchen
            # Option 1 client identifier
            response_ascii += BuildOption(1, Transactions[transaction_id].DUID)
            # Option 2 server identifier
            response_ascii += BuildOption(2, cfg.SERVERDUID)

            # IA_NA non-temporary addresses
            # Option 3 + 5 Identity Association for Non-temporary Address
            if 3 in options_request:
                # sicherheitshalber noch mal pruefen ob wirklich eine MAC ueber die Link Local IP vom Client bekannt ist
                if Transactions[transaction_id].ClientLLIP in CollectedMACs:
                    # sammle IA Informationen ueber Client in storage
                    if Transactions[transaction_id].Client == None:
                        Transactions[transaction_id].Client = BuildClient(transaction_id)
                    # embed option 5 into option 3 - several if necessary
                    ia_addresses = ""
                    for address in Transactions[transaction_id].Client.Addresses:
                        if address.IA_TYPE == "na":
                            ipv6_address = binascii.b2a_hex(socket.inet_pton(socket.AF_INET6, address.ADDRESS))
                            # if a transaction consists of too many requests from client -
                            # - might be caused by going wild windows clients -
                            # reset all adddresses with lifetime 0
                            # lets start with maximal transaction count of 10
                            if Transactions[transaction_id].Counter < 10:
                                preferred_lifetime = "%08x" % (int(address.PREFERRED_LIFETIME))
                                valid_lifetime = "%08x" % (int(address.VALID_LIFETIME))
                            else:
                                preferred_lifetime = "%08x" % (0)
                                valid_lifetime = "%08x" % (0)
                            ia_address = BuildOption(5, ipv6_address + preferred_lifetime + valid_lifetime)
                            ia_addresses += ia_address
                    if not ia_addresses == "":
                        #
                        # todo: default clients sometimes seem to have class ""
                        #
                        if Transactions[transaction_id].Client.Class != "":
                            t1 = "%08x" % (int(cfg.CLASSES[Transactions[transaction_id].Client.Class].T1))
                            t2 = "%08x" % (int(cfg.CLASSES[Transactions[transaction_id].Client.Class].T2))
                        else:
                            t1 = "%08x" % (int(cfg.T1))
                            t2 = "%08x" % (int(cfg.T2))

                        ia_na = BuildOption(3, Transactions[transaction_id].IAID + t1 + t2 + ia_addresses)
                        response_ascii += ia_na
                                               
            # IA_TA temporary addresses
            if 4 in options_request:
                # sicherheitshalber noch mal pruefen ob wirklich eine MAC ueber die Link Local IP vom Client bekannt ist
                if Transactions[transaction_id].ClientLLIP in CollectedMACs:
                    # sammle IA Informationen ueber Client in storage
                    Transactions[transaction_id].Client = BuildClient(transaction_id)
                    # embed option 5 into option 4 - several if necessary
                    ia_addresses = ""
                    for address in Transactions[transaction_id].Client.Addresses:
                        if address.IA_TYPE == "ta":
                            # if a transaction consists of too many requests from client -
                            # - might be caused by going wild windows clients -
                            # reset all adddresses with lifetime 0
                            # lets start with maximal transaction count of 10
                            if Transactions[transaction_id].Counter < 10:
                                preferred_lifetime = "%08x" % (int(address.PREFERRED_LIFETIME))
                                valid_lifetime = "%08x" % (int(address.VALID_LIFETIME))
                            else:
                                preferred_lifetime = "%08x" % (0)
                                valid_lifetime = "%08x" % (0)
                            ia_address = BuildOption(5, ipv6_address + preferred_lifetime + valid_lifetime)
                            ia_addresses += ia_address
                    if not ia_addresses == "":
                        ia_ta = BuildOption(4, Transactions[transaction_id].IAID + ia_addresses)
                        response_ascii += ia_ta

            # Option 7 Server Preference
            if 7 in options_request:
                response_ascii += BuildOption(7, "%02x" % (int(cfg.SERVER_PREFERENCE)))

            # Option 11 Authentication Option
            # seems to be pretty unused at the moment - to be done
            if 11 in options_request:
                # "3" fuer Reconfigure Key Authentication Protocol
                protocol = "%02x" % (3)
                # "1" fuer Algorithmus
                algorithm = "%02x" % (1)
                # tja, vermuten wir mal "0" als gueltige Replay Detection Method
                rdm = "%02x" % (0)
                # Replay Detection - nehmen wir einfach mal die aktuelle Zeit
                replay_detection = "%016x" % (int(datetime.datetime.now().strftime("%s")))
                # Authentication Information Type
                # ist bei erstem Senden 1, spaeter, bei HMAC-MD5, dann 2
                ai_type = "%02x" % (1)
                authentication_information = cfg.AUTHENTICATION_INFORMATION
                # alles zusammen....
                response_ascii += BuildOption(11, protocol + algorithm + rdm + replay_detection + ai_type + authentication_information)            

            # Option 12 Server Unicast Option
            if 12 in options_request:
                response_ascii += BuildOption(12, binascii.b2a_hex(socket.inet_pton(socket.AF_INET6, cfg.ADDRESS)))

            # Option 13 Status Code Option - statuscode is taken from dictionary
            if 13 in options_request:
                response_ascii += BuildOption(13, "%04x" % (status))

            # Option 14 Rapid Commit Option - necessary for REPLY to SOLICIT message with Rapid Commit
            if 14 in options_request:
                response_ascii += BuildOption(14, "")

            # Option 23 DNS recursive name server
            if 23 in options_request:
                if len(cfg.NAMESERVER) > 0 or cfg.CLASSES[Transactions[transaction_id].Client.Class].NAMESERVER:
                    # in case several nameservers are given convert them all and add them
                    nameserver = ""                   
                    # if the class has its own nameserver use them, otherwise the general ones
                    if cfg.CLASSES[Transactions[transaction_id].Client.Class].NAMESERVER:
                        for ns in cfg.CLASSES[Transactions[transaction_id].Client.Class].NAMESERVER:
                            nameserver += socket.inet_pton(socket.AF_INET6, ns)
                    else:
                        for ns in cfg.NAMESERVER:
                            nameserver += socket.inet_pton(socket.AF_INET6, ns)
                    response_ascii += BuildOption(23, binascii.b2a_hex(nameserver))

            # Option 24 Domain Search List
            if 24 in options_request:
                response_ascii += BuildOption(24, ConvertDNS2Binary(cfg.DOMAIN))

            # Option 31 OPTION_SNTP_SERVERS
            #if 31 in options_request and cfg.SNTP_SERVERS != "":
            #    sntp_servers = ""
            #    for s in cfg.SNTP_SERVERS:
            #        sntp_server = binascii.b2a_hex(socket.inet_pton(socket.AF_INET6, s))
            #        sntp_servers += sntp_server
            #    response_ascii += BuildOption(31, sntp_servers)

            # Option 32 Information Refresh Time
            if 32 in options_request:
                response_ascii += BuildOption(32, "%08x" % int(cfg.INFORMATION_REFRESH_TIME))        

            # Option 39 FQDN
            # http://tools.ietf.org/html/rfc4704#page-5
            # regarding RFC 4704 5. there are 3 kinds of client behaviour for N O S:
            # - client wants to update DNS itself -> sends 0 0 0
            # - client wants server to update DNS -> sends 0 0 1
            # - client wants no server DNS update -> sends 1 0 0
            if 39 in options_request:
                # flags for answer
                N, O, S = 0, 0, 0  
                # use hostname supplied by client
                if cfg.DNS_USE_CLIENT_HOSTNAME and not cfg.DNS_IGNORE_CLIENT:
                    hostname = Transactions[transaction_id].Hostname
                # use hostname from config
                else:
                    hostname = Transactions[transaction_id].Client.Hostname
                if not hostname == "":                   
                    if cfg.DNS_UPDATE == 1:
                        # DNS update done by server - don't care what client wants
                        if cfg.DNS_IGNORE_CLIENT:
                            S = 1
                            O = 1
                        else:
                            # honor the client's request for the server to initiate DNS updates
                            if Transactions[transaction_id].DNS_S == 1:
                                S = 1
                            # honor the client's request for no server-initiated DNS update
                            elif  Transactions[transaction_id].DNS_N == 1:
                                N = 1  
                    else:
                        # no DNS update at all, not for server and not for client
                        if Transactions[transaction_id].DNS_N == 1 or\
                           Transactions[transaction_id].DNS_S == 1:
                            O = 1
                            
                    # sum of flags
                    nos_flags = N*4 + O*2 + S*1
                    
                    response_ascii += BuildOption(39, "%02x" % (nos_flags) + ConvertDNS2Binary(hostname+"."+cfg.DOMAIN))
                else:
                    # if no hostname given put something in and force client override
                    response_ascii += BuildOption(39, "%02x" % (3) + ConvertDNS2Binary("invalid-hostname"))

            # self.finish() sends self.response
            self.response = binascii.a2b_hex(response_ascii)
            # log client info
            if not Transactions[transaction_id].Client == None and 3 in options_request:
                Log("%s: TransactionID: %s Options: %s %s" % (MESSAGE_TYPES[response_type], transaction_id, options_request, Transactions[transaction_id].Client._getOptionsString()))
            else:
                Log("%s: TransactionID: %s Options:%s" % (MESSAGE_TYPES[response_type], transaction_id, options_request))

        except Exception, err:
            Log("ERROR: Response(): " + str(err))
            print err
            import traceback
            traceback.print_exc(file=sys.stdout)

            # clear any response
            self.response = ""
            return None


    def finish(self):
        """
            send response from self.response
        """
        # send only if there is anything to send
        if cfg.REALLY_DO_IT and len(self.response) > 0:
            self.socket.sendto(self.response, self.client_address)
        else:
            print "send nothing..."

### MAIN ###

if __name__ == "__main__":

    print "Starting dhcpy6d daemon..."
    Log("Starting dhcpy6d daemon...")

    # configure SocketServer
    UDPMulticastIPv6.address_family = socket.AF_INET6
    server = UDPMulticastIPv6(("", 547), Handler)

    # start query queue watcher
    configqueryqueuewatcher = QueryQueue(cfg, configstore, configqueryqueue, configanswerqueue)
    configqueryqueuewatcher.start()
    volatilequeryqueuewatcher = QueryQueue(cfg, volatilestore, volatilequeryqueue, volatileanswerqueue)
    volatilequeryqueuewatcher.start()

    # collect all known MAC addresses from database
    volatilestore.CollectMACsFromDB()

    # start TidyUp thread for cleaning in background
    tidyup = TidyUpThread()
    tidyup.start()

    # start DNS query queue to care for DNS in background    
    dnsquery = DNSQueryThread(dnsqueue)
    dnsquery.start()

    # server forever :-)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)

    # close logfile
    if cfg.LOG and cfg.LOG_FILE != "":
        Logfile.close()
