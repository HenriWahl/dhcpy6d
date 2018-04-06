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
import ConfigParser
import stat
import os
import os.path
import uuid
import time
import shlex
import copy
import platform
import pwd
import grp
import getopt
import re
import ctypes

from helpers import *

# use ctypes for libc access in get_libc from helpers
LIBC = get_libc()

# needed for boolean options
BOOLPOOL = {'0':False, '1':True, 'no':False, 'yes':True, 'false':False, 'true':True, False:False, True:True, 'on':True, 'off':False}

# whitespace for options with more than one value
WHITESPACE = ' ,'

# empty default prefix - if needed given by command line argument
PREFIX = ''

# default usage text - to be extended
USAGE = '''
dhcpy6d - DHCPv6 server

Usage: dhcpy6d --config <file> [--user <user>] [--group <group>] [--duid <duid>] [--prefix <prefix>] [--really-do-it <yes>|<no>]

       dhcpy6d --message '<message>'
       
       dhcpy6d --generate-duid

See manpage dhcpy6d(8) for details.
'''


def generate_duid():
    return '00010001%08x%012x' % (time.time(), uuid.getnode())


class Config(object):
    '''
      general settings
    '''

    def __init__(self):
        '''
            define defaults
        '''
        # access dynamic PREFIX
        global PREFIX
        self.PREFIX = PREFIX

        # default settings
        # Server cfg.INTERFACE + addresses
        self.INTERFACE = 'eth0'
        self.MCAST = 'ff02::1:2'
        self.PORT = '547'
        self.ADDRESS = '2001:db8::1'
        # effective user and group - will have to be set mainly by distribution package
        self.USER = 'root'
        self.GROUP = 'root'
        # lets make the water turn black... or build a shiny server DUID
        # in case someone will ever debug something here: Wireshark shows
        # year 2042 even if it is 2012 - time itself is OK
        self.SERVERDUID = generate_duid()
        self.NAMESERVER = ''

        # domain for FQDN hostnames
        self.DOMAIN = 'domain'
        # domain search list for option 24, according to RFC 3646
        # defaults to DOMAIN
        self.DOMAIN_SEARCH_LIST = ''

        # IA_NA Options
        # Default preferred lifetime for addresses
        self.PREFERRED_LIFETIME = '5400'
        # Default valid lifetime for addresses
        self.VALID_LIFETIME = '7200'
        # T1 RENEW
        self.T1 = '2700'
        # T2 REBIND
        self.T2 = '4050'

        # Server Preference
        self.SERVER_PREFERENCE = '255'

        # SNTP SERVERS Option 31
        # Unused!
        #self.SNTP_SERVERS = [ self.ADDRESS ]

        # NTP server Option 56
        self.NTP_SERVER = ''
        # Auxiliary options, derived from self.NTP_SERVER
        self.NTP_SERVER_SRV = []
        self.NTP_SERVER_MC = []
        self.NTP_SERVER_FQDN = []

        # INFORMATION REFRESH TIME option 32 for option 11 (INFORMATION REQUEST)
        # see RFC http://tools.ietf.org/html/rfc4242
        self.INFORMATION_REFRESH_TIME = '6000'

        # config type
        # one of file, mysql, sqlite or none
        self.STORE_CONFIG = 'none'
        # one of mysql or sqlite
        self.STORE_VOLATILE = 'sqlite'

        # file for client information
        self.STORE_FILE_CONFIG = 'clients.conf'

        # DB data
        self.STORE_DB_HOST = 'localhost'
        self.STORE_DB_DB = 'dhcpy6d'
        self.STORE_DB_USER = 'user'
        self.STORE_DB_PASSWORD = 'password'

        self.STORE_SQLITE_CONFIG = 'config.sqlite'
        self.STORE_SQLITE_VOLATILE = 'volatile.sqlite'

        # whether MAC-LLIP pairs should be stored forever or retrieved freshly if needed
        self.CACHE_MAC_LLIP = 'False'

        # DNS Update settings
        self.DNS_UPDATE = 'False'
        self.DNS_UPDATE_NAMESERVER = '::1'
        self.DNS_TTL = 86400
        self.DNS_RNDC_KEY = 'rndc-key'
        self.DNS_RNDC_SECRET = '0000000000000000000000000000000000000000000000000000000000000'
        # DNS RFC 4704 client DNS wishes
        # use client supplied hostname
        self.DNS_USE_CLIENT_HOSTNAME = 'False'
        # ignore client ideas about DNS (if at all, what name to use, self-updating...)
        self.DNS_IGNORE_CLIENT = 'True'

        # Log ot not
        self.LOG = 'False'
        # Log level
        self.LOG_LEVEL = 'INFO'
        # Log on console
        self.LOG_CONSOLE = 'False'
        # Logfile
        self.LOG_FILE = ''
        # Log to syslog
        self.LOG_SYSLOG = 'False'
        # Syslog facility
        self.LOG_SYSLOG_FACILITY = 'daemon'
        # Local syslog socket or server:port
        if platform.system() in ['Linux', 'OpenBSD']:
            self.LOG_SYSLOG_DESTINATION = '/dev/log'
        else:
            self.LOG_SYSLOG_DESTINATION = '/var/run/log'

        # log newly found MAC addresses - if CACHE_MAC_LLIP is false this might be way too much
        self.LOG_MAC_LLIP = 'False'

        # some 128 bits
        self.AUTHENTICATION_INFORMATION = '00000000000000000000000000000000'

        # for debugging - if False nothing is done
        self.REALLY_DO_IT = 'False'

        # interval for TidyUp thread - time to sleep in TidyUpThread
        self.CLEANING_INTERVAL = 5

        # sddress and class schemes
        self.ADDRESSES = dict()
        self.CLASSES = dict()
        self.PREFIXES = dict()

        # how to identify clients
        self.IDENTIFICATION = 'mac'
        self.IDENTIFICATION_MODE = 'match_all'

        # allow to ignore IAIDs which play no big role at all for server
        self.IGNORE_IAID = 'False'

        # regexp filters for hostnames etc.
        self.FILTERS = {'mac':[], 'duid':[], 'hostname':[]}

        # define a fallback default class and address scheme
        self.ADDRESSES['default'] = Address(ia_type='na',
                                            category='mac',
                                            pattern='fdef::$mac$',
                                            aclass='default',
                                            atype='default',
                                            prototype='fdef0000000000000000XXXXXXXXXXXX')

        # define dummy address scheme for fixed addresses
        # pattern and prototype are not really needed as this
        # addresses are fixed
        self.ADDRESSES['fixed'] = Address(ia_type='na',
                                          category='fixed',
                                          pattern='fdef::1',
                                          aclass='default',
                                          atype='fixed',
                                          prototype='fdef0000000000000000000000000000')

        self.PREFIXES['default'] = Prefix(pattern='fdef:$range$::',
                                          prange='1000-1fff',
                                          category='range')

        self.CLASSES['default'] = Class()
        self.CLASSES['default'].ADDRESSES.append('default')
        self.CLASSES['default'].PREFIXES.append('default')

        # config file from command line
        # default config file and cli values
        configfile = self.cli_options = self.cli_user = self.cli_group = self.cli_duid = self.cli_really_do_it = None
        # get multiple options
        try:
            self.cli_options, cli_remains = getopt.gnu_getopt(sys.argv[1:],
                                                              'c:u:g:d:r:p:m:G',
                                                              ['config=',
                                                               'user=',
                                                               'group=',
                                                               'duid=',
                                                               'really-do-it=',
                                                               'prefix=',
                                                               'message=',
                                                               'generate-duid'])
            for opt, arg in self.cli_options:
                if opt in ('-c', '--config'):
                    configfile = arg
                if opt in ('-g', '--group'):
                    self.cli_group = arg
                if opt in ('-u', '--user'):
                    self.cli_user = arg
                if opt in ('-d', '--duid'):
                    self.cli_duid = arg
                if opt in ('-r', '--really-do-it'):
                    self.cli_really_do_it = arg
                if opt in ('-p', '--prefix'):
                    PREFIX = arg
                    self.PREFIX = PREFIX
                if opt in ('-m', '--message'):
                    send_control_message(arg)
                    sys.exit(0)
                if opt in ('-G', '--generate-duid'):
                    print generate_duid()
                    sys.exit(0)

        except getopt.GetoptError, err:
            print err
            print USAGE
            sys.exit(1)

        if configfile == None:
            error_exit('No config file given - please use --config <config.file>')

        if os.path.exists(configfile):
            if not (os.path.isfile(configfile) or
               os.path.islink(configfile)):
                error_exit("Configuration file '%s' is no file or link." % (configfile))
        else:
            error_exit("Configuration file '%s' does not exist." % (configfile))

        # read config at once
        self.read_config(configfile)


    def read_config(self, configfile):
        '''
            read configuration from file, should work with included files too - at least this is the plan
        '''

        # instantiate Configparser
        config = ConfigParser.ConfigParser()
        config.read(configfile)

        # whyever sections classes get overwritten sometimes and so some configs had been missing
        # so create classes and addresses here
        for section in config.sections():
            if section.startswith('class_'):
                self.CLASSES[section.split('class_')[1]] = Class(name=section.split('class_')[1].strip())
            if section.startswith('address_'):
                self.ADDRESSES[section.split('address_')[1].strip()] = Address()
            if section.startswith('prefix_'):
                self.PREFIXES[section.split('prefix_')[1].strip()] = Prefix()

        for section in config.sections():
            # go through all items
            for item in config.items(section):
                if section.upper() == 'DHCPY6D':
                    # check for legacy settings - STORE_MYSQL_* will be replaced by STORE_DB_* since 0.4.2
                    # see https://github.com/HenriWahl/dhcpy6d/issues/3
                    if item[0].upper() in ('STORE_MYSQL_HOST', 'STORE_MYSQL_DB', 'STORE_MYSQL_USER', 'STORE_MYSQL_PASSWORD'):
                        sys.stderr.write("\nWARNING: Keyword '%s' in section '[%s]' is deprecated and should be replaced by '%s'.\n\n" \
                                         % (item[0], section, item[0].lower().replace('mysql', 'db')))
                        # rename setting from *_MYSQL_* to *_DB_*
                        object.__setattr__(self, item[0].upper().replace('MYSQL', 'DB'), str(item[1]).strip())

                    # check if keyword is known - if not, exit
                    elif not item[0].upper() in self.__dict__:
                        error_exit("Keyword '%s' in section '[%s]' of configuration file '%s' is unknown." % (item[0], section, configfile))
                    # ConfigParser seems to be not case sensitive so settings get normalized
                    else:
                        object.__setattr__(self, item[0].upper(), str(item[1]).strip())
                else:
                    # global address schemes
                    if section.lower().startswith('address_'):
                        # check if keyword is known - if not, exit
                        if item[0].upper() == 'PREFIX_LENGTH':
                            # Show a warning because there are no prefix lenghts in DHCPv6
                            sys.stderr.write("\nWARNING: Keyword '%s' in section '[%s]' is deprecated and should be removed.\n\n" \
                                             % (item[0], section))
                        else:
                            if not item[0].upper() in self.ADDRESSES[section.lower().split('address_')[1]].__dict__:
                                error_exit("Keyword '%s' in section '[%s]' of configuration file '%s' is unknown." %
                                           (item[0], section, configfile))
                        self.ADDRESSES[section.lower().split('address_')[1]].__setattr__(item[0].upper(), str(item[1]).strip())

                    # global prefix schemes
                    if section.lower().startswith('prefix_'):
                        if not item[0].upper() in self.PREFIXES[section.lower().split('prefix_')[1]].__dict__:
                            error_exit("Keyword '%s' in section '[%s]' of configuration file '%s' is unknown." %
                                       (item[0], section, configfile))
                        self.PREFIXES[section.lower().split('prefix_')[1]].__setattr__(item[0].upper(), str(item[1]).strip())

                    # global classes with their addresses
                    elif section.lower().startswith('class_'):
                        # check if keyword is known - if not, exit
                        if not item[0].upper() in self.CLASSES[section.lower().split('class_')[1]].__dict__:
                            error_exit("Keyword '%s' in section '[%s]' of configuration file '%s' is unknown." % (item[0], section, configfile))
                        if item[0].upper() == 'ADDRESSES':
                            # strip whitespace and separators of addresses
                            lex = shlex.shlex(item[1])
                            lex.whitespace = WHITESPACE
                            lex.wordchars += ':.'
                            for address in lex:
                                if len(address) > 0:
                                    self.CLASSES[section.lower().split('class_')[1]].ADDRESSES.append(address)
                        elif item[0].upper() == 'PREFIXES':
                            # strip whitespace and separators of prefixes
                            lex = shlex.shlex(item[1])
                            lex.whitespace = WHITESPACE
                            lex.wordchars += ':.'
                            for prefix in lex:
                                if len(prefix) > 0:
                                    self.CLASSES[section.lower().split('class_')[1]].PREFIXES.append(prefix)
                        elif item[0].upper() == 'ADVERTISE':
                            # strip whitespace and separators of advertised IAs
                            lex = shlex.shlex(item[1])
                            lex.whitespace = WHITESPACE
                            lex.wordchars += ':.'
                            self.CLASSES[section.lower().split('class_')[1]].ADVERTISE[:] = []
                            for advertise in lex:
                                if len(advertise) > 0:
                                    self.CLASSES[section.lower().split('class_')[1]].ADVERTISE.append(advertise)
                        elif item[0].upper() == 'INTERFACE':
                            # strip whitespace and separators of interfaces
                            lex = shlex.shlex(item[1])
                            lex.whitespace = WHITESPACE
                            lex.wordchars += ':.'
                            for interface in lex:
                                if not interface in self.INTERFACE:
                                    error_exit("Interface '%s' used in section '[%s]' of configuration file '%s' is not defined in general settings." % (interface, section, configfile))
                        else:
                            self.CLASSES[section.lower().split('class_')[1]].__setattr__(item[0].upper(), str(item[1]).strip())

        # The next paragraphs contain finetuning
        self.IDENTIFICATION = listify_option(self.IDENTIFICATION)

        # get interfaces as list
        self.INTERFACE = listify_option(self.INTERFACE)

        # create default classes for each interface - if not defined
        # derive from default 'default' class
        for i in self.INTERFACE:
            if not 'default_' + i in self.CLASSES:
                self.CLASSES['default_' + i] = copy.copy(self.CLASSES['default'])
                self.CLASSES['default_' + i].NAME = 'default_' + i
                self.CLASSES['default_' + i].INTERFACE = i

        # lower storage
        self.STORE_CONFIG = self.STORE_CONFIG.lower()
        self.STORE_VOLATILE = self.STORE_VOLATILE.lower()

        # boolize none-config-store
        if self.STORE_CONFIG.lower() == 'none':
            self.STORE_CONFIG = False

        # if no domain search list has been given use DOMAIN
        if len(self.DOMAIN_SEARCH_LIST) == 0:
            self.DOMAIN_SEARCH_LIST = self.DOMAIN

        # domain search list has to be a list
        self.DOMAIN_SEARCH_LIST = listify_option(self.DOMAIN_SEARCH_LIST)

        # get nameservers as list
        if len(self.NAMESERVER) > 0:
            self.NAMESERVER = listify_option(self.NAMESERVER)

        # get NTP servers as list
        if len(self.NTP_SERVER) > 0:
            self.NTP_SERVER = listify_option(self.NTP_SERVER)

        # convert to boolean value
        self.DNS_UPDATE = BOOLPOOL[self.DNS_UPDATE.lower()]
        self.DNS_USE_CLIENT_HOSTNAME = BOOLPOOL[self.DNS_USE_CLIENT_HOSTNAME.lower()]
        self.DNS_IGNORE_CLIENT = BOOLPOOL[self.DNS_IGNORE_CLIENT.lower()]
        self.REALLY_DO_IT = BOOLPOOL[self.REALLY_DO_IT.lower()]
        self.LOG = BOOLPOOL[self.LOG.lower()]
        self.LOG_CONSOLE = BOOLPOOL[self.LOG_CONSOLE.lower()]
        self.LOG_LEVEL = self.LOG_LEVEL.upper()
        self.LOG_SYSLOG = BOOLPOOL[self.LOG_SYSLOG.lower()]
        self.CACHE_MAC_LLIP = BOOLPOOL[self.CACHE_MAC_LLIP.lower()]
        self.LOG_MAC_LLIP = BOOLPOOL[self.LOG_MAC_LLIP.lower()]
        self.IGNORE_IAID = BOOLPOOL[self.IGNORE_IAID.lower()]

        self.LOG_SYSLOG_FACILITY = self.LOG_SYSLOG_FACILITY.upper()

        # index of classes which add some identification rules etc.
        for c in self.CLASSES.values():
            if c.FILTER_MAC != '': self.FILTERS['mac'].append(c)
            if c.FILTER_DUID != '': self.FILTERS['duid'].append(c)
            if c.FILTER_HOSTNAME != '': self.FILTERS['hostname'].append(c)
            if c.NAMESERVER != '': c.NAMESERVER = listify_option(c.NAMESERVER)
            if c.NTP_SERVER != '': c.NTP_SERVER = listify_option(c.NTP_SERVER)
            if c.INTERFACE != '':
                c.INTERFACE = listify_option(c.INTERFACE)
            else:
                # use general setting if none specified
                c.INTERFACE = self.INTERFACE
            # use default T1 and T2 if not defined
            if c.T1 == 0: c.T1 = self.T1
            if c.T2 == 0: c.T2 = self.T2
            # check advertised IA types - if empty default to ['addresses']
            if len(c.ADVERTISE) == 0:
                c.ADVERTISE = ['addresses', 'prefixes']

        # set type properties for addresses
        for a in self.ADDRESSES:
            # name for address, important for leases db
            self.ADDRESSES[a].TYPE = a
            if self.ADDRESSES[a].VALID_LIFETIME == 0: self.ADDRESSES[a].VALID_LIFETIME = self.VALID_LIFETIME
            if self.ADDRESSES[a].PREFERRED_LIFETIME == 0: self.ADDRESSES[a].PREFERRED_LIFETIME = self.PREFERRED_LIFETIME
            # normalize ranges
            self.ADDRESSES[a].RANGE = self.ADDRESSES[a].RANGE.lower()
            # convert boolean string to boolean value
            self.ADDRESSES[a].DNS_UPDATE = BOOLPOOL[self.ADDRESSES[a].DNS_UPDATE]
            if self.ADDRESSES[a].DNS_ZONE == '': self.ADDRESSES[a].DNS_ZONE = self.DOMAIN
            if self.ADDRESSES[a].DNS_TTL == '0': self.ADDRESSES[a].DNS_TTL = self.DNS_TTL
            # add prototype for later fast validity comparison of rebinding leases
            # also use as proof of validity of address patterns
            self.ADDRESSES[a].build_prototype()

        # set type properties for prefixes
        for p in self.PREFIXES:
            # name for address, important for leases db
            self.PREFIXES[p].TYPE = p
            if self.PREFIXES[p].VALID_LIFETIME == 0: self.PREFIXES[p].VALID_LIFETIME = self.VALID_LIFETIME
            if self.PREFIXES[p].PREFERRED_LIFETIME == 0: self.PREFIXES[p].PREFERRED_LIFETIME = self.PREFERRED_LIFETIME
            # normalize ranges
            self.PREFIXES[p].RANGE = self.PREFIXES[p].RANGE.lower()
            # route via Link Local Address
            self.PREFIXES[p].ROUTE_LINK_LOCAL = BOOLPOOL[self.PREFIXES[p].ROUTE_LINK_LOCAL]
            # add prototype for later fast validity comparison of rebinding leases
            # also use as proof of validity of address patterns
            self.PREFIXES[p].build_prototype()

        # check if some options are set by cli options
        if not self.cli_user == None:
            self.USER = self.cli_user
        if not self.cli_group == None:
            self.GROUP = self.cli_group
        if not self.cli_duid == None:
            self.SERVERDUID = self.cli_duid
        if not self.cli_really_do_it == None:
            self.REALLY_DO_IT = BOOLPOOL[self.cli_really_do_it.lower()]

        # check config
        msg_prefix = 'General configuration:'

        # check user and group
        try:
            pwd.getpwnam(self.USER)
        except:
            error_exit("%s User '%s' does not exist" % (msg_prefix, self.USER))
        try:
            grp.getgrnam(self.GROUP)
        except:
            error_exit("%s Group '%s' does not exist" % (msg_prefix, self.GROUP))

        # check interface
        for i in self.INTERFACE:
            # also accept Linux VLAN and other definitions but interface must exist
            if LIBC.if_nametoindex(i) == 0 or not re.match('^[a-z0-9_:.%-]*$', i, re.IGNORECASE):
                error_exit("%s Interface '%s' is unknown." % (msg_prefix, i))

        # check multicast address
        try:
            decompress_ip6(self.MCAST)
        except Exception, err:
            error_exit("%s Multicast address '%s' is invalid." % (msg_prefix, err))
        if not self.MCAST.lower().startswith('ff'):
            error_exit("Multicast address '%s' is invalid." % (msg_prefix))

        # check DHCPv6 port
        if not self.PORT.isdigit():
            error_exit("%s Port '%s' is invalid" % (msg_prefix, self.PORT))
        elif not 0 < int(self.PORT) <= 65535:
            error_exit("%s Port '%s' is invalid" % (msg_prefix, self.PORT))

        # check server's address
        try:
            decompress_ip6(self.ADDRESS)
        except Exception, err:
            error_exit("%s Server address '%s' is invalid." % (msg_prefix, err))

        # check server duid
        if not self.SERVERDUID.isalnum():
            error_exit("%s Server DUID '%s' must be alphanumeric." % (msg_prefix, self.SERVERDUID))

        # check nameserver to be given to client
        for nameserver in self.NAMESERVER:
            try:
                decompress_ip6(nameserver)
            except Exception, err:
                error_exit("%s Name server address '%s' is invalid." % (msg_prefix, err))

        # split NTP server types into possible 3 (address, multicast, FQDN)
        # more details about this madness are available at https://tools.ietf.org/html/rfc5908
        for ntp_server in self.NTP_SERVER:
            try:
                decompress_ip6(ntp_server)
                # if decompressing worked it must be an address
                if ntp_server.lower().startswith('ff'):
                    self.NTP_SERVER_MC.append(ntp_server.lower())
                else:
                    self.NTP_SERVER_SRV.append(ntp_server.lower())
            except Exception, err:
                if re.match('^[a-z0-9.-]*$', ntp_server, re.IGNORECASE):
                    self.NTP_SERVER_FQDN.append(ntp_server.lower())
                else:
                    error_exit("%s NTP server address '%s' is invalid." % (msg_prefix, ntp_server))

        # partly check of domain name validity
        if not re.match('^[a-z0-9.-]*$', self.DOMAIN, re.IGNORECASE):
            error_exit("%s Domain name '%s' is invalid." % (msg_prefix, self.DOMAIN))

        # partly check of domain name validity
        if not self.DOMAIN.lower()[0].isalpha() or \
           not self.DOMAIN.lower()[-1].isalpha():
                error_exit("%s Domain name '%s' is invalid." % (msg_prefix, self.DOMAIN))

        # check domain search list domains
        for d in self.DOMAIN_SEARCH_LIST:
            # partly check of domain name validity
            if not re.match('^[a-z0-9.-]*$', d, re.IGNORECASE):
                error_exit("%s Domain search list domain name '%s' is invalid." % (msg_prefix, d))

            # partly check of domain name validity
            if not d.lower()[0].isalpha() or \
               not d.lower()[-1].isalpha():
                    error_exit("%s Domain search list domain name '%s' is invalid." % (msg_prefix, d))

        # check if valid lifetime is a number
        if not self.VALID_LIFETIME.isdigit():
            error_exit("%s Valid lifetime '%s' is invalid." % (msg_prefix, self.VALID_LIFETIME))

        # check if preferred lifetime is a number
        if not self.PREFERRED_LIFETIME.isdigit():
            error_exit("%s Preferred lifetime '%s' is invalid." % (msg_prefix, self.PREFERRED_LIFETIME))

        # check if valid lifetime is longer than preferred lifetime
        if not int(self.VALID_LIFETIME) > int(self.PREFERRED_LIFETIME):
            error_exit("%s Valid lifetime '%s' is shorter than preferred lifetime '%s' and thus invalid." %
                       (msg_prefix, self.VALID_LIFETIME, self.PREFERRED_LIFETIME))

        # check if T1 is a number
        if not self.T1.isdigit():
            error_exit("%s T1 '%s' is invalid." % (msg_prefix, self.T1))

        # check if T2 is a number
        if not self.T2.isdigit():
            error_exit("%s T2 '%s' is invalid." % (msg_prefix, self.T2))

        # check T2 is not smaller than T1
        if not int(self.T2) >= int(self.T1):
            error_exit("%s T2 '%s' is shorter than T1 '%s' and thus invalid." %
                       (msg_prefix, self.T2, self.T1))

        # check if T1 <= T2 <= PREFERRED_LIFETIME <= VALID_LIFETIME
        if not (int(self.T1) <= int(self.T2) <= int(self.PREFERRED_LIFETIME) <= int(self.VALID_LIFETIME)):
            error_exit("%s Time intervals T1 '%s' <= T2 '%s' <= preferred_lifetime '%s' <= valid_lifetime '%s' are wrong." %
                       (msg_prefix, self.T1, self.T2, self.PREFERRED_LIFETIME, self.VALID_LIFETIME))

        # check server preference
        if not self.SERVER_PREFERENCE.isdigit():
            error_exit("%s Server preference '%s' is invalid." % (msg_prefix, self.SERVER_PREFERENCE))
        elif not 0 <= int(self.SERVER_PREFERENCE) <= 255:
            error_exit("Server preference '%s' is invalid" % (self.SERVER_PREFERENCE))

        # check information refresh time
        if not self.INFORMATION_REFRESH_TIME.isdigit():
            error_exit("%s Information refresh time '%s' is invalid." % (msg_prefix, self.INFORMATION_REFRESH_TIME))
        elif not 0 < int(self.INFORMATION_REFRESH_TIME):
            error_exit("%s Information refresh time preference '%s' is pretty short." % (msg_prefix, self.INFORMATION_REFRESH_TIME))

        # check validity of configuration source
        if not self.STORE_CONFIG in ['mysql', 'postgresql', 'sqlite', 'file', False]:
            error_exit("%s Unknown config storage type '%s' is invalid." % (msg_prefix, self.STORAGE))

        # check which type of storage to use for leases
        if not self.STORE_VOLATILE in ['mysql', 'postgresql', 'sqlite']:
            error_exit("%s Unknown volatile storage type '%s' is invalid." % (msg_prefix, self.VOLATILE))

        # check if database for config and volatile is equal - if any
        if self.STORE_CONFIG in ['mysql', 'postgresql'] and self.STORE_VOLATILE in ['mysql', 'postgresql']:
            if not self.STORE_CONFIG == self.STORE_VOLATILE:
                error_exit("%s Storage types for database access have to be equal - '%s' != '%s'." % (msg_prefix,
                                                                                                      self.STORE_CONFIG,
                                                                                                      self.STORE_VOLATILE,))

        # check validity of config file
        if self.STORE_CONFIG == 'file':
            if os.path.exists(self.STORE_FILE_CONFIG):
                if not (os.path.isfile(self.STORE_FILE_CONFIG) or
                   os.path.islink(self.STORE_FILE_CONFIG)):
                    error_exit("%s Config file '%s' is no file or link." % (msg_prefix, self.STORE_FILE_CONFIG))
            else:
                error_exit("%s Config file '%s' does not exist." % (msg_prefix, self.STORE_FILE_CONFIG))

        # check validity of config db sqlite file
        if self.STORE_CONFIG == 'sqlite':
            if os.path.exists(self.STORE_SQLITE_CONFIG):
                if not (os.path.isfile(self.STORE_SQLITE_CONFIG) or
                   os.path.islink(self.STORE_SQLITE_CONFIG)):
                    error_exit("%s SQLite file '%s' is no file or link." % (msg_prefix, self.STORE_SQLITE_CONFIG))
            else:
                error_exit("%s SQLite file '%s' does not exist." % (msg_prefix, self.STORE_SQLITE_CONFIG))

        # check validity of volatile db sqlite file
        if self.STORE_VOLATILE == 'sqlite':
            if os.path.exists(self.STORE_SQLITE_VOLATILE):
                if not (os.path.isfile(self.STORE_SQLITE_VOLATILE) or
                   os.path.islink(self.STORE_SQLITE_VOLATILE)):
                    error_exit("%s SQLite file '%s' is no file or link." % (msg_prefix, self.STORE_SQLITE_VOLATILE))
            else:
                error_exit("%s SQLite file '%s' does not exist." % (msg_prefix, self.STORE_SQLITE_VOLATILE))

        # check log validity
        if self.LOG:
            if self.LOG_FILE != '':
                if os.path.exists(self.LOG_FILE):
                    if not (os.path.isfile(self.LOG_FILE) or
                       os.path.islink(self.LOG_FILE)):
                        error_exit("%s Logfile '%s' is no file or link." % (msg_prefix, self.LOG_FILE))
                else:
                    error_exit("%s Logfile '%s' does not exist." % (msg_prefix, self.LOG_FILE))
                # check ownership of logfile
                stat_result = os.stat(self.LOG_FILE)
                if not stat_result.st_uid == pwd.getpwnam(self.USER).pw_uid:
                    error_exit("%s User %s is not owner of logfile '%s'." % (msg_prefix, self.USER, self.LOG_FILE))
                if not stat_result.st_gid == grp.getgrnam(self.GROUP).gr_gid:
                    error_exit("%s Group %s is not owner of logfile '%s'." % (msg_prefix, self.GROUP, self.LOG_FILE))
            else:
                error_exit('%s No logfile configured.' % (msg_prefix))

            if not self.LOG_LEVEL in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
                error_exit("Log level '%s' is invalid" % (self.LOG_LEVEL))
            if self.LOG_SYSLOG:
                if not self.LOG_SYSLOG_FACILITY in ['KERN', 'USER', 'MAIL', 'DAEMON', 'AUTH',
                                                     'LPR', 'NEWS', 'UUCP', 'CRON', 'SYSLOG',
                                                     'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3',
                                                     'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7']:
                    error_exit("%s Syslog facility '%s' is invalid." % (msg_prefix, self.LOG_SYSLOG_FACILITY))

                if self.LOG_SYSLOG_DESTINATION.startswith('/'):
                    stat_result = os.stat(self.LOG_SYSLOG_DESTINATION)
                    if not stat.S_ISSOCK(stat_result.st_mode):
                        error_exit("%s Syslog destination '%s' is no socket." % (msg_prefix, self.LOG_SYSLOG_DESTINATION))
                elif self.LOG_SYSLOG_DESTINATION.count(':') > 0:
                    if self.LOG_SYSLOG_DESTINATION.count(':') > 1:
                        error_exit("%s Syslog destination '%s' is no valid host:port destination." % (msg_prefix, self.LOG_SYSLOG_DESTINATION))

        # check authentification information
        if not self.AUTHENTICATION_INFORMATION.isalnum():
            error_exit("%s Authentification information '%s' must be alphanumeric." % (msg_prefix, self.AUTHENTICATION_INFORMATION))

        # check validity of identification attributes
        for i in self.IDENTIFICATION:
            if not i in ['mac', 'hostname', 'duid']:
                error_exit("%s Identification must consist of 'mac', 'hostname' and/or 'duid'." % (msg_prefix))

        # check validity of identification mode
        if not self.IDENTIFICATION_MODE.strip() in ['match_all', 'match_some']:
            error_exit("%s Identification mode must be one of 'match_all' or 'macht_some'." % (msg_prefix))

        # cruise through classes
        # more checks to come...
        for c in self.CLASSES:
            msg_prefix = "Class '%s':" % (c)
            if not self.CLASSES[c].ANSWER in ['normal', 'noaddress', 'none']:
                error_exit("%s answer type must be one of 'normal', 'noaddress' and 'none'." % (msg_prefix))

            # check interface
            for i in self.CLASSES[c].INTERFACE:
                # also accept Linux VLAN and other definitions but interface must exist
                if LIBC.if_nametoindex(i) == 0 or not re.match('^[a-z0-9_:.%-]*$', i, re.IGNORECASE):
                    error_exit("%s Interface '%s' is invalid." % (msg_prefix, i))

            # check advertised IA types
            for i in self.CLASSES[c].ADVERTISE:
                if not i in ['addresses', 'prefixes']:
                    error_exit("Only 'addresses' and 'prefixes' can be advertised.")

            # check nameserver to be given to client
            for nameserver in self.CLASSES[c].NAMESERVER:
                try:
                    decompress_ip6(nameserver)
                except Exception, err:
                    error_exit("%s Name server address '%s' is invalid." % (msg_prefix, err))

            # split NTP server types into possible 3 (address, multicast, FQDN)
            # more details about this madness are available at https://tools.ietf.org/html/rfc5908
            for ntp_server in self.CLASSES[c].NTP_SERVER:
                try:
                    decompress_ip6(ntp_server)
                    # if decompressing worked it must be an address
                    if ntp_server.lower().startswith('ff'):
                        self.CLASSES[c].NTP_SERVER_MC.append(ntp_server.lower())
                    else:
                        self.CLASSES[c].NTP_SERVER_SRV.append(ntp_server.lower())
                except Exception, err:
                    if re.match('^[a-z0-9.-]*$', ntp_server, re.IGNORECASE):
                        self.CLASSES[c].NTP_SERVER_FQDN.append(ntp_server.lower())
                    else:
                        error_exit("%s NTP server address '%s' is invalid." % (msg_prefix, ntp_server))

            # check if T1 is a number
            if not self.CLASSES[c].T1.isdigit():
                error_exit("%s T1 '%s' is invalid." % (msg_prefix, self.CLASSES[c].T1))

            # check if T2 is a number
            if not self.CLASSES[c].T2.isdigit():
                error_exit("%s T2 '%s' is invalid." % (msg_prefix, self.CLASSES[c].T2))

            # check T2 is not smaller than T1
            if not int(self.CLASSES[c].T2) >= int(self.CLASSES[c].T1):
                error_exit("%s T2 '%s' is shorter than T1 '%s' and thus invalid." % \
                           (msg_prefix, self.CLASSES[c].T2, self.CLASSES[c].T1))

            # check every single address of a class
            for a in self.CLASSES[c].ADDRESSES:
                msg_prefix = "Class '%s' Address type '%s':" % (c, a)
                # test if used addresses are defined
                if not a in self.ADDRESSES:
                    error_exit("%s Address type '%s' is not defined." % (msg_prefix, a))

                # test validity of category
                if not self.ADDRESSES[a].CATEGORY.strip() in ['fixed', 'range', 'random', 'mac', 'id', 'dns']:
                    error_exit("%s Category '%s' is invalid. Category must be one of 'fixed', 'range', 'random', 'mac', 'id' and 'dns'." % (msg_prefix, self.ADDRESSES[a].CATEGORY))

                # test validity of pattern - has its own error output
                self.ADDRESSES[a].build_prototype()
                # test existence of category specific variable in pattern
                if self.ADDRESSES[a].CATEGORY == 'range':
                    if not re.match('^[0-9a-f]{1,4}\-[0-9a-f]{1,4}$', self.ADDRESSES[a].RANGE, re.IGNORECASE):
                        error_exit("%s Range '%s' is not valid." % \
                                   (msg_prefix, self.ADDRESSES[a].RANGE))
                    if not 0 < self.ADDRESSES[a].PATTERN.count('$range$') < 2:
                        error_exit("%s Pattern '%s' contains wrong number of '$range$' variables for category 'range'." % \
                                   (msg_prefix, self.ADDRESSES[a].PATTERN.strip()))
                    elif not self.ADDRESSES[a].PATTERN.endswith('$range$'):
                        error_exit("%s Pattern '%s' must end with '$range$' variable for category 'range'." % \
                                   (msg_prefix, self.ADDRESSES[a].PATTERN.strip()))

                if self.ADDRESSES[a].CATEGORY == 'mac':
                    if not 0 < self.ADDRESSES[a].PATTERN.count('$mac$') < 2:
                        error_exit("%s Pattern '%s' contains wrong number of '$mac$' variables for category 'mac'." % \
                                   (msg_prefix, self.ADDRESSES[a].PATTERN.strip()))

                if self.ADDRESSES[a].CATEGORY == 'id':
                    if not self.ADDRESSES[a].PATTERN.count('$id$') == 1:
                        error_exit("%s Pattern '%s' contains wrong number of '$id$' variables for category 'id'." % \
                                   (msg_prefix, self.ADDRESSES[a].PATTERN.strip()))

                if self.ADDRESSES[a].CATEGORY == 'random':
                    if not self.ADDRESSES[a].PATTERN.count('$random64$') == 1:
                        error_exit("%s Pattern '%s' contains wrong number of '$random64$' variables for category 'random'." % \
                                   (msg_prefix, self.ADDRESSES[a].PATTERN.strip()))

                if self.ADDRESSES[a].CATEGORY == 'dns':
                    if not len(self.NAMESERVER) > 0:
                        error_exit("Address of category 'dns' needs a set nameserver.")

                # check ia_type
                if not self.ADDRESSES[a].IA_TYPE.strip().lower() in ['na', 'ta']:
                    error_exit("%s: IA type '%s' must be one of 'na' or 'ta'." % (msg_prefix, self.ADDRESSES[a].IA_TYPE.strip()))

                # check if valid lifetime is a number
                if not self.ADDRESSES[a].VALID_LIFETIME.isdigit():
                    error_exit("%s Valid lifetime '%s' is invalid." % (msg_prefix, self.ADDRESSES[a].VALID_LIFETIME))

                # check if preferred lifetime is a number
                if not self.ADDRESSES[a].PREFERRED_LIFETIME.isdigit():
                    error_exit("%s Preferred lifetime '%s' is invalid." % (msg_prefix, self.ADDRESSES[a].PREFERRED_LIFETIME))

                # check if valid lifetime is longer than preferred lifetime
                if not int(self.ADDRESSES[a].VALID_LIFETIME) >= int(self.ADDRESSES[a].PREFERRED_LIFETIME):
                    error_exit("%s Valid lifetime '%s' is shorter than preferred lifetime '%s' and thus invalid." % \
                               (msg_prefix, self.ADDRESSES[a].VALID_LIFETIME, self.ADDRESSES[a].PREFERRED_LIFETIME))

                # check if T1 <= T2 <= PREFERRED_LIFETIME <= VALID_LIFETIME
                if not (int(self.CLASSES[c].T1) <= int(self.CLASSES[c].T2) <=\
                        int(self.ADDRESSES[a].PREFERRED_LIFETIME) <= int(self.ADDRESSES[a].VALID_LIFETIME)):
                    error_exit("%s Time intervals T1 '%s' <= T2 '%s' <= preferred_lifetime '%s' <= valid_lifetime '%s' are wrong." % \
                               (msg_prefix, self.CLASSES[c].T1, self.CLASSES[c].T2,
                               self.ADDRESSES[a].PREFERRED_LIFETIME, self.ADDRESSES[a].VALID_LIFETIME))

            # check every single prefix of a class
            for p in self.CLASSES[c].PREFIXES:
                msg_prefix = "Class '%s' PREFIX type '%s':" % (c, p)
                # test if used addresses are defined
                if not p in self.PREFIXES:
                    error_exit("%s Prefix type '%s' is not defined." % (msg_prefix, p))

                # test validity of category
                if not self.PREFIXES[p].CATEGORY.strip() in ['range']:
                    error_exit("%s Category '%s' is invalid. Category must be 'range' right now." % (msg_prefix, self.PREFIXES[p].CATEGORY))

                # test validity of pattern - has its own error output
                self.PREFIXES[p].build_prototype()
                # test existence of category specific variable in pattern
                if self.PREFIXES[p].CATEGORY == 'range':
                    if not re.match('^[0-9a-f]{1,4}\-[0-9a-f]{1,4}$', self.PREFIXES[p].RANGE, re.IGNORECASE):
                        error_exit("%s Range '%s' is not valid." % \
                                   (msg_prefix, self.PREFIXES[p].RANGE))
                    if not 0 < self.PREFIXES[p].PATTERN.count('$range$') < 2:
                        error_exit("%s Pattern '%s' contains wrong number of '$range$' variables for category 'range'." % \
                                   (msg_prefix, self.PREFIXES[p].PATTERN.strip()))
                    elif self.PREFIXES[p].PATTERN.endswith('$range$'):
                        error_exit("%s Pattern '%s' must not end with '$range$' variable for category 'range'." % \
                                   (msg_prefix, self.PREFIXES[p].PATTERN.strip()))

                # check if valid lifetime is a number
                if not self.PREFIXES[p].VALID_LIFETIME.isdigit():
                    error_exit("%s Valid lifetime '%s' is invalid." % (msg_prefix, self.PREFIXES[p].VALID_LIFETIME))

                # check if preferred lifetime is a number
                if not self.PREFIXES[p].PREFERRED_LIFETIME.isdigit():
                    error_exit("%s Preferred lifetime '%s' is invalid." % (msg_prefix, self.PREFIXES[p].PREFERRED_LIFETIME))

                # check if valid lifetime is longer than preferred lifetime
                if not int(self.PREFIXES[p].VALID_LIFETIME) >= int(self.PREFIXES[p].PREFERRED_LIFETIME):
                    error_exit("%s Valid lifetime '%s' is shorter than preferred lifetime '%s' and thus invalid." % \
                               (msg_prefix, self.PREFIXES[p].VALID_LIFETIME, self.PREFIXES[p].PREFERRED_LIFETIME))

                # check if T1 <= T2 <= PREFERRED_LIFETIME <= VALID_LIFETIME
                if not (int(self.CLASSES[c].T1) <= int(self.CLASSES[c].T2) <=
                        int(self.PREFIXES[p].PREFERRED_LIFETIME) <= int(self.PREFIXES[p].VALID_LIFETIME)):
                    error_exit("%s Time intervals T1 '%s' <= T2 '%s' <= preferred_lifetime '%s' <= valid_lifetime '%s' are wrong." % \
                               (msg_prefix, self.CLASSES[c].T1, self.CLASSES[c].T2,
                               self.PREFIXES[p].PREFERRED_LIFETIME, self.PREFIXES[p].VALID_LIFETIME))

                # check if prefix is a valid number
                if not self.PREFIXES[p].LENGTH.isdigit():
                    error_exit("%s Prefix length '%s' is invalid." % (msg_prefix, self.PREFIXES[p].LENGTH))
                if not 0 <= int(self.PREFIXES[p].LENGTH) <= 128:
                    error_exit("%s Prefix length '%s' must be in range 0-128." % (msg_prefix, self.PREFIXES[p].LENGTH))


class ConfigObject(object):
    """
        class providing methods both for addresses and prefixes
    """

    def build_prototype(self, pattern=None):
        '''
            build prototype of pattern for later comparison with leases
        '''

        # if called with de-$prefix$-ed pattern use it
        if pattern == None:
            prototype = self.PATTERN
        else:
            prototype = pattern

        # inject prefix later so jump out here now
        if '$prefix$' in prototype:
            self.PROTOTYPE = prototype
            return

        # check different client address categories - to be extended!
        if self.CATEGORY in ['mac', 'id', 'range', 'random']:
            if self.CATEGORY == 'mac':
                prototype = prototype.replace('$mac$', 'XXXX:XXXX:XXXX')
            elif self.CATEGORY == 'id':
                prototype = prototype.replace('$id$', 'XXXX')
            elif self.CATEGORY == 'random':
                prototype = prototype.replace('$random64$', 'XXXX:XXXX:XXXX:XXXX')
            elif self.CATEGORY == 'range':
                prototype = prototype.replace('$range$', 'XXXX')
            try:
                # build complete 'address' and ignore all the Xs (strict=False)
                prototype = decompress_ip6(prototype, strict=False)
            except Exception, err:
                error_exit("Address type '%s' address pattern '%s' is not valid: %s" % (self.TYPE, self.PATTERN, err))

        self.PROTOTYPE = prototype


    def inject_dynamic_prefix_into_prototype(self, dynamic_prefix):
        '''
            called from main to put then known dynamic prefix into protoype
        '''
        if '$prefix$' in self.PATTERN:
            prefix_pattern = self.PATTERN.replace('$prefix$', dynamic_prefix)
            self.build_prototype(prefix_pattern)


    def matches_prototype(self, address):
        '''
            test if given address matches prototype and therefore this address' DNS zone
            information might be used
            only used for address types, not client instances
        '''
        match = False
        # compare all chars of address and prototype, if they do match or
        # prototype has placeholder X return finally True, otherwise stop
        # at the first difference and give back False
        for i in range(32):
            if self.PROTOTYPE[i] == address[i] or self.PROTOTYPE[i] == 'X':
                match = True
            else:
                match = False
                break
        return match


class Address(ConfigObject):
    '''
        class for address definition, used for config
    '''
    def __init__(self,
                 address=None,
                 ia_type='na',
                 category='random',
                 pattern='2001:db8::$random64$',
                 preferred_lifetime=0,
                 valid_lifetime=0,
                 atype='default',
                 aclass='default',
                 prototype='',
                 arange='',
                 dns_update=False,
                 dns_zone='',
                 dns_rev_zone='0.8.b.d.1.0.0.2.ip6.arpa',
                 dns_ttl='0',
                 valid=True):
        self.CATEGORY = category
        self.PATTERN = pattern
        self.IA_TYPE = ia_type
        self.PREFERRED_LIFETIME = preferred_lifetime
        self.VALID_LIFETIME = valid_lifetime
        self.ADDRESS = address
        self.RANGE = arange.lower()
        # because 'class' is a python keyword we use 'aclass' here
        self.CLASS = aclass
        # same with type
        self.TYPE = atype
        # a prototypical address to be compared with leases given by
        # clients - if prototype and lease address kind of match
        # give back the lease as valid
        self.PROTOTYPE = prototype
        # flag for updating address in DNS or not
        self.DNS_UPDATE = dns_update
        # DNS zone data
        self.DNS_ZONE = dns_zone.lower()
        self.DNS_REV_ZONE = dns_rev_zone.lower()
        self.DNS_TTL = dns_ttl
        # flag invalid addresses as invalid, valid ones as valid
        self.VALID = valid


class Prefix(ConfigObject):
    """
        class for delegated prefix definition
    """
    def __init__(self,
                 prefix=None,
                 pattern='2001:db8:$range$::',
                 prange='1000-1fff',
                 category='range',
                 length='48',
                 preferred_lifetime=0,
                 valid_lifetime=0,
                 ptype='default',
                 pclass='default',
                 valid=True,
                 route_link_local=False):
        self.PREFIX = prefix
        self.PATTERN = pattern
        self.RANGE = prange.lower()
        self.CATEGORY = category
        self.LENGTH = length
        self.PREFERRED_LIFETIME = preferred_lifetime
        self.VALID_LIFETIME = valid_lifetime
        self.TYPE = ptype
        self.CLASS = pclass
        self.VALID = valid
        self.ROUTE_LINK_LOCAL = route_link_local


class Class(object):
    '''
        class for class definition
    '''
    def __init__(self, name=''):
        self.NAME = name
        self.ADDRESSES = list()
        self.PREFIXES = list()
        self.NAMESERVER = ''
        self.NTP_SERVER = ''
        self.FILTER_MAC = ''
        self.FILTER_HOSTNAME = ''
        self.FILTER_DUID = ''
        self.IDENTIFICATION_MODE = 'match_all'
        # RENEW time
        self.T1 = 0
        # REBIND time
        self.T2 = 0
        # at which interface this class of clients is served
        self.INTERFACE = ''
        # in certain cases it might be useful not to give any address to clients, for example if only a defined group
        # of hosts should get IPv6 addresses and others not. They will get a 'NoAddrsAvail' response if this option
        # is set to 'noaddress' or no answer at all if set to 'none'
        self.ANSWER = 'normal'
        # which IA_* should this class supply - addresses, prefixes or both?
        # shouldn't be an empty list because in this case the class would not make sense at all
        # as default both will be advertised
        self.ADVERTISE = ['addresses', 'prefixes']
        self.CALL_UP = ''
        self.CALL_DOWN = ''
