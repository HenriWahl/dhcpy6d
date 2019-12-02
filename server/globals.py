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

import queue
import platform
import sys
import time

import dns

from server.config import cfg
from server.storage import (DBMySQL,
                            DBPostgreSQL,
                            SQLite,
                            Store,
                            Textfile)

# if nameserver is given create resolver
if len(cfg.NAMESERVER) > 0:
    # default nameservers for DNS queries
    resolver_query = dns.resolver.Resolver()
    resolver_query.nameservers = cfg.NAMESERVER

# RNDC Key for DNS updates from ISC Bind /etc/rndc.key
if cfg.DNS_UPDATE:
    import dns.update
    import dns.tsigkeyring

    Keyring = dns.tsigkeyring.from_text({cfg.DNS_RNDC_KEY : cfg.DNS_RNDC_SECRET})

    # resolver for DNS updates
    resolver_update = dns.resolver.Resolver()
    resolver_update.nameservers = [cfg.DNS_UPDATE_NAMESERVER]

# dictionary to store transactions - key is transaction ID, value a transaction object
Transactions = dict()

# collected MAC addresses from clients, mapping to link local IPs
CollectedMACs = dict()

# queues for queries
configquery_queue = queue.Queue()
configanswer_queue = queue.Queue()
volatilequery_queue = queue.Queue()
volatileanswer_queue = queue.Queue()

# queue for dns actualization
dnsquery_queue = queue.Queue()

# queue for executing some script to modify routes after delegating prefixes
route_queue = queue.Queue()

# attempt to log connections and count them to find out which clients do silly crazy brute force
requests = dict()
requests_blacklist = dict()

# global time variable, synchronized by TimerThread
timer = int(time.time())

# save OS
OS = platform.system()
if 'BSD' in OS:
    OS = 'BSD'

# platform-dependant neighbor cache call
# every platform has its different output
# dev, llip and mac are positions of output of call
# len is minimal length a line has to have to be evaluable
#
# update: has been different to Linux which now access neighbor cache natively
NC = { 'BSD': { 'call' : '/usr/sbin/ndp -a -n',
                'dev'  : 2,
                'llip' : 0,
                'mac'  : 1,
                'len'  : 3},
       'Darwin': { 'call' : '/usr/sbin/ndp -a -n',
                   'dev'  : 2,
                   'llip' : 0,
                   'mac'  : 1,
                   'len'  : 3}
            }

# libc access via ctypes, needed for interface handling, get it by helpers.get_libc()
# obsolete in Python 3
# LIBC = get_libc()

# index IF name > number, gets filled in UDPMulticastIPv6
IF_NAME = dict()
# index IF number > name
IF_NUMBER = dict()

# IA_NA, IA_TA and IA_PD Options referred here in handler
IA_OPTIONS = (3, 4, 25)

# options to be ignored when logging
# IGNORED_LOG_OPTIONS = ['OptionsRaw', 'Client', 'ClientConfigDB', 'Timestamp', 'DUIDLLAddress', 'DUIDType', 'IAT1', 'IAT2', 'IP6_old', 'LLIP_old']
IGNORED_LOG_OPTIONS = ['OptionsRaw', 'Client', 'ClientConfigDB', 'Timestamp', 'IAT1', 'IAT2', 'IP6_old', 'LLIP_old']

# empty options string test
EMPTY_OPTIONS = [None, False, '', []]

# dummy IAID for transactions
DUMMY_IAID = '00000000'

# dummy MAC for transactions
DUMMY_MAC = '00:00:00:00:00:00'

# store
# because of thread trouble there should not be too much db connections at once
# so we need to use the queryqueue way - subject to change
# source of configuration of hosts
# use client configuration only if needed
if cfg.STORE_CONFIG:
    if cfg.STORE_CONFIG == 'file':
        configstore = Textfile(cfg, configquery_queue, configanswer_queue, Transactions, CollectedMACs)
    if cfg.STORE_CONFIG == 'mysql':
        configstore = DBMySQL(cfg, configquery_queue, configanswer_queue, Transactions, CollectedMACs)
    if cfg.STORE_CONFIG == 'postgresql':
        configstore = DBPostgreSQL(cfg, configquery_queue, configanswer_queue, Transactions, CollectedMACs)
    if cfg.STORE_CONFIG == 'sqlite':
        configstore = SQLite(cfg, configquery_queue, configanswer_queue, Transactions, CollectedMACs, storage_type='config')
else:
    # dummy configstore if no client config is needed
    configstore = Store(cfg, configquery_queue, configanswer_queue, Transactions, CollectedMACs)
    # 'none' store is always connected
    configstore.connected = True

# storage for changing data like leases, LLIPs, DUIDs etc.
if cfg.STORE_VOLATILE == 'mysql':
    volatilestore = DBMySQL(cfg, volatilequery_queue, volatileanswer_queue, Transactions, CollectedMACs)
if cfg.STORE_VOLATILE == 'postgresql':
    volatilestore = DBPostgreSQL(cfg, volatilequery_queue, volatileanswer_queue, Transactions, CollectedMACs)
if cfg.STORE_VOLATILE == 'sqlite':
    volatilestore = SQLite(cfg, volatilequery_queue, volatileanswer_queue, Transactions, CollectedMACs, storage_type='volatile')

# do not start if no database connection exists
if not configstore.connected:
    print('\nConfiguration database is not connected!\n')
    sys.exit(1)
if not volatilestore.connected:
    print('\nDatabase for volatile data is not connected!\n')
    sys.exit(1)