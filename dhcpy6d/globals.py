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

import queue
import platform
import time

import dns.resolver

from .config import cfg
from .constants import CONST

# if nameserver is given create resolver
if len(cfg.NAMESERVER) > 0:
    # default nameservers for DNS queries
    resolver_query = dns.resolver.Resolver()
    resolver_query.nameservers = cfg.NAMESERVER
else:
    resolver_query = None

# RNDC Key for DNS updates from ISC Bind /etc/rndc.key
if cfg.DNS_UPDATE:
    import dns.update
    import dns.tsigkeyring

    keyring = dns.tsigkeyring.from_text({cfg.DNS_RNDC_KEY: cfg.DNS_RNDC_SECRET})

    # resolver for DNS updates
    resolver_update = dns.resolver.Resolver()
    resolver_update.nameservers = [cfg.DNS_UPDATE_NAMESERVER]
else:
    resolver_update = None
    keyring = None


class Timer:
    """
    global object containing time set by TimerThread
    """
    __time = 0

    def __init__(self):
        self.time = time.time()

    @property
    def time(self):
        return self.__time

    @time.setter
    def time(self, new_time):
        self.__time = int(new_time)


# global time variable, synchronized by TimerThread
timer = Timer()

# dictionary to store transactions - key is transaction ID, value a transaction object
transactions = {}
# collected MAC addresses from clients, mapping to link local IPs
collected_macs = {}

# queues for queries
config_query_queue = queue.Queue()
config_answer_queue = queue.Queue()
volatile_query_queue = queue.Queue()
volatile_answer_queue = queue.Queue()

# queue for dns actualization
dns_query_queue = queue.Queue()

# queue for executing some script to modify routes after delegating prefixes
route_queue = queue.Queue()

# attempt to log connections and count them to find out which clients do silly crazy brute force
requests = {}
requests_blacklist = {}

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
NC = {'BSD': {'call': '/usr/sbin/ndp -a -n',
              'dev': 2,
              'llip': 0,
              'mac': 1,
              'len': 3},
      'Darwin': {'call': '/usr/sbin/ndp -a -n',
                 'dev': 2,
                 'llip': 0,
                 'mac': 1,
                 'len': 3}
      }

# libc access via ctypes, needed for interface handling, get it by helpers.get_libc()
# obsolete in Python 3
# LIBC = get_libc()

# index IF name > number, gets filled in UDPMulticastIPv6
IF_NAME = {}
# index IF number > name
IF_NUMBER = {}

# IA_NA, IA_TA and IA_PD Options referred here in handler
IA_OPTIONS = (CONST.OPTION.IA_NA,
              CONST.OPTION.IA_TA,
              CONST.OPTION.IA_PD)

# options to be ignored when logging
IGNORED_LOG_OPTIONS = ['options_raw', 'client', 'client_config_db', 'timestamp', 'iat1', 'iat2', 'id']

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
config_store = volatile_store = None
