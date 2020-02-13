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

import configparser
import copy
import getopt
import grp
import os
import os.path
import platform
import pwd
import re
import shlex
import stat
import sys
import time
import uuid

from .helpers import (decompress_ip6,
                      error_exit,
                      get_interfaces,
                      listify_option,
                      send_control_message)

# needed for boolean options
BOOLPOOL = {'0': False, '1': True, 'no': False, 'yes': True, 'false': False, 'true': True, False: False, True: True,
            'on': True, 'off': False}

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


class Config:
    """
      general settings
    """

    def __init__(self):
        """
            define defaults
        """
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
        self.SNTP_SERVERS = ''

        # NTP server Option 56
        self.NTP_SERVER = ''
        # Auxiliary options, derived from self.NTP_SERVER
        self.NTP_SERVER_DICT = {'SRV': [], 'MC': [], 'FQDN': []}

        # INFORMATION REFRESH TIME option 32 for option 11 (INFORMATION REQUEST)
        # see RFC http://tools.ietf.org/html/rfc4242
        self.INFORMATION_REFRESH_TIME = '6000'

        # config type
        # one of file, mysql, sqlite or none
        self.STORE_CONFIG = 'none'
        # one of mysql or sqlite
        self.STORE_VOLATILE = 'sqlite'

        # file for client information
        self.STORE_FILE_CONFIG = '/etc/dhcpy6d-clients.conf'

        # DB data
        self.STORE_DB_HOST = 'localhost'
        self.STORE_DB_DB = 'dhcpy6d'
        self.STORE_DB_USER = 'user'
        self.STORE_DB_PASSWORD = 'password'

        self.STORE_SQLITE_CONFIG = 'config.sqlite'
        self.STORE_SQLITE_VOLATILE = '/var/lib/dhcpy6d/volatile.sqlite'

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
        self.CLEANING_INTERVAL = 10

        # sddress, bootfile and class schemes
        self.ADDRESSES = {}
        self.BOOTFILES = {}
        self.CLASSES = {}
        self.PREFIXES = {}

        # how to identify clients
        self.IDENTIFICATION = 'mac'
        self.IDENTIFICATION_MODE = 'match_all'

        # allow to ignore IAIDs which play no big role at all for server
        self.IGNORE_IAID = 'False'

        # ignore clients which do no appear in the neighbor cache table
        self.IGNORE_UNKNOWN_CLIENTS = 'True'

        # ignore MAC addresses as identifier - useful for neighbor-cache-less interfaces like ppp0
        self.IGNORE_MAC = 'False'

        # ignore interface to be able to listen on dynamically created interfaces like ppp
        self.IGNORE_INTERFACE = 'False'

        # allow setting request rate limits to put clients onto blacklist
        self.REQUEST_LIMIT = 'no'
        self.REQUEST_LIMIT_TIME = '60'
        self.REQUEST_LIMIT_COUNT = '20'
        self.REQUEST_LIMIT_RELEASE_TIME = '7200'
        self.REQUEST_LIMIT_IDENTIFICATION = 'llip'

        # restore still valid routes at startup and remove inactive ones
        self.MANAGE_ROUTES_AT_START = 'False'

        # regexp filters for hostnames etc.
        self.FILTERS = {'mac': [], 'duid': [], 'hostname': []}

        # define a fallback default class and address scheme
        self.ADDRESSES['default'] = Address(ia_type='na',
                                            category='mac',
                                            pattern='fdef::$mac$',
                                            aclass='default',
                                            atype='default',
                                            prototype='fdef0000000000000000xxxxxxxxxxxx')

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
                    print(generate_duid())
                    sys.exit(0)

        except getopt.GetoptError as err:
            print(err)
            print(USAGE)
            sys.exit(1)

        if configfile is None:
            error_exit('No config file given - please use --config <config.file>')

        if os.path.exists(configfile):
            if not (os.path.isfile(configfile) or
                    os.path.islink(configfile)):
                error_exit(f"Configuration file '{configfile}' is no file or link.")
        else:
            error_exit(f"Configuration file '{configfile}' does not exist.")

        # read config at once
        self.read_config(configfile)

    def read_config(self, configfile):
        """
            read configuration from file, should work with included files too - at least this is the plan
        """

        # instantiate Configparser
        config = configparser.ConfigParser()
        config.read(configfile)

        # whyever sections classes get overwritten sometimes and so some configs had been missing
        # so create classes and addresses here
        for section in config.sections():
            # global PXE boot url schemes
            if section.startswith('bootfile_'):
                self.BOOTFILES[section.split('bootfile_')[1]] = BootFile(name=section.split('bootfile_')[1].strip())
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
                    if item[0].upper() in ('STORE_MYSQL_HOST',
                                           'STORE_MYSQL_DB',
                                           'STORE_MYSQL_USER',
                                           'STORE_MYSQL_PASSWORD'):
                        sys.stderr.write(f"\nWARNING: Keyword '{item[0]}' in section '[{section}]' "
                                         f"is deprecated and should be replaced "
                                         f"by '{item[0].lower().replace('mysql', 'db')}'.\n\n")
                        object.__setattr__(self, item[0].upper().replace('MYSQL', 'DB'), str(item[1]).strip())

                    # check if keyword is known - if not, exit
                    elif not item[0].upper() in self.__dict__:
                        error_exit(f"Keyword '{item[0]}' in section '[{section}]' "
                                   f"of configuration file '{configfile}' is unknown.")
                    # ConfigParser seems to be not case sensitive so settings get normalized
                    else:
                        object.__setattr__(self, item[0].upper(), str(item[1]).strip())
                else:
                    # global PXE boot url schemes
                    if section.lower().startswith('bootfile_'):
                        if not item[0].upper() in self.BOOTFILES[section.lower().split('bootfile_')[1]].__dict__:
                            error_exit(f"Keyword '{item[0]}' in section '[{section}]' "
                                       f"of configuration file '{configfile}' is unknown.")
                        self.BOOTFILES[section.lower().split('bootfile_')[1]].__setattr__(item[0].upper(),
                                                                                          str(item[1]).strip())
                    # global address schemes
                    if section.lower().startswith('address_'):
                        # check if keyword is known - if not, exit
                        if item[0].upper() == 'PREFIX_LENGTH':
                            # Show a warning because there are no prefix lenghts in DHCPv6
                            sys.stderr.write(f"\nWARNING: Keyword '{item[0]}' in section '{section}' is deprecated "
                                             "and should be removed.\n\n")
                        else:
                            if not item[0].upper() in self.ADDRESSES[section.lower().split('address_')[1]].__dict__:
                                error_exit(f"Keyword '{item[0]}' in section '[{section}]' "
                                           f"of configuration file '{configfile}' is unknown.")
                        self.ADDRESSES[section.lower().split('address_')[1]].__setattr__(item[0].upper(),
                                                                                         str(item[1]).strip())

                    # global prefix schemes
                    if section.lower().startswith('prefix_'):
                        if not item[0].upper() in self.PREFIXES[section.lower().split('prefix_')[1]].__dict__:
                            error_exit(f"Keyword '{item[0]}' in section '[{section}]' "
                                       f"of configuration file '{configfile}' is unknown.")
                        self.PREFIXES[section.lower().split('prefix_')[1]].__setattr__(item[0].upper(),
                                                                                       str(item[1]).strip())

                    # global classes with their addresses
                    elif section.lower().startswith('class_'):
                        # check if keyword is known - if not, exit
                        if not item[0].upper() in self.CLASSES[section.lower().split('class_')[1]].__dict__:
                            error_exit(f"Keyword '{item[0]}' in section '[{section}]' "
                                       f"of configuration file '{configfile}' is unknown.")
                        if item[0].upper() == 'ADDRESSES':
                            # strip whitespace and separators of addresses
                            lex = shlex.shlex(item[1])
                            lex.whitespace = WHITESPACE
                            lex.wordchars += ':.'
                            for address in lex:
                                if len(address) > 0:
                                    self.CLASSES[section.lower().split('class_')[1]].ADDRESSES.append(address)
                        elif item[0].upper() == 'BOOTFILES':
                            # strip whitespace and separators of bootfiles
                            lex = shlex.shlex(item[1])
                            lex.whitespace = WHITESPACE
                            lex.wordchars += ':.'
                            for bootfile in lex:
                                if len(bootfile) > 0:
                                    self.CLASSES[section.lower().split('class_')[1]].BOOTFILES.append(bootfile)
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
                                if interface not in self.INTERFACE:
                                    error_exit(f"Interface '{interface}' used in section '[{section}]' "
                                               f"of configuration file '{configfile}' is not "
                                               "defined in general settings.")
                        else:
                            self.CLASSES[section.lower().split('class_')[1]].__setattr__(item[0].upper(),
                                                                                         str(item[1]).strip())

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

        # option 31 quite probably is obsolete but might still be used, so just take its values from newer option 56
        # client dhcpcd for example uses this option when asking for NTP server
        if len(self.SNTP_SERVERS) > 0:
            self.SNTP_SERVERS = listify_option(self.SNTP_SERVERS)
        elif len(self.NTP_SERVER) > 0:
            self.SNTP_SERVERS = listify_option(self.NTP_SERVER)

        # get NTP servers as list
        if len(self.NTP_SERVER) > 0:
            self.NTP_SERVER = listify_option(self.NTP_SERVER)

        # convert to boolean values
        for option in ['DNS_UPDATE',
                       'DNS_USE_CLIENT_HOSTNAME',
                       'DNS_IGNORE_CLIENT',
                       'REALLY_DO_IT',
                       'LOG',
                       'LOG_CONSOLE',
                       'LOG_SYSLOG',
                       'CACHE_MAC_LLIP',
                       'LOG_MAC_LLIP',
                       'IGNORE_IAID',
                       'IGNORE_UNKNOWN_CLIENTS',
                       'IGNORE_MAC',
                       'IGNORE_INTERFACE',
                       'REQUEST_LIMIT',
                       'MANAGE_ROUTES_AT_START']:
            try:
                self.__dict__[option] = BOOLPOOL[self.__dict__[option].lower()]
            except:
                error_exit(f"Option '{option.lower()}' only allows boolean values like 'yes' and 'no'.")

        # upperize for syslog
        self.LOG_SYSLOG_FACILITY = self.LOG_SYSLOG_FACILITY.upper()
        self.LOG_LEVEL = self.LOG_LEVEL.upper()

        # index of classes which add some identification rules etc.
        for c in list(self.CLASSES.values()):
            if c.FILTER_MAC != '':
                self.FILTERS['mac'].append(c)
            if c.FILTER_DUID != '':
                self.FILTERS['duid'].append(c)
            if c.FILTER_HOSTNAME != '':
                self.FILTERS['hostname'].append(c)
            if c.NAMESERVER != '':
                c.NAMESERVER = listify_option(c.NAMESERVER)
            if c.NTP_SERVER != '':
                c.NTP_SERVER = listify_option(c.NTP_SERVER)
            if c.INTERFACE != '':
                c.INTERFACE = listify_option(c.INTERFACE)
            else:
                # use general setting if none specified
                c.INTERFACE = self.INTERFACE
            # use default T1 and T2 if not defined
            if c.T1 == 0:
                c.T1 = self.T1
            if c.T2 == 0:
                c.T2 = self.T2
            # check advertised IA types - if empty default to ['addresses']
            if len(c.ADVERTISE) == 0:
                c.ADVERTISE = ['addresses', 'prefixes']

        # set type properties for addresses
        for a in self.ADDRESSES:
            # name for address, important for leases db
            self.ADDRESSES[a].TYPE = a
            if self.ADDRESSES[a].VALID_LIFETIME == 0:
                self.ADDRESSES[a].VALID_LIFETIME = self.VALID_LIFETIME
            if self.ADDRESSES[a].PREFERRED_LIFETIME == 0:
                self.ADDRESSES[a].PREFERRED_LIFETIME = self.PREFERRED_LIFETIME
            # normalize ranges
            self.ADDRESSES[a].RANGE = self.ADDRESSES[a].RANGE.lower()
            # convert boolean string to boolean value
            self.ADDRESSES[a].DNS_UPDATE = BOOLPOOL[self.ADDRESSES[a].DNS_UPDATE]
            if self.ADDRESSES[a].DNS_ZONE == '':
                self.ADDRESSES[a].DNS_ZONE = self.DOMAIN
            if self.ADDRESSES[a].DNS_TTL == '0':
                self.ADDRESSES[a].DNS_TTL = self.DNS_TTL
            # add prototype for later fast validity comparison of rebinding leases
            # also use as proof of validity of address patterns
            self.ADDRESSES[a].build_prototype()

        # set type properties for prefixes
        for p in self.PREFIXES:
            # name for address, important for leases db
            self.PREFIXES[p].TYPE = p
            if self.PREFIXES[p].VALID_LIFETIME == 0:
                self.PREFIXES[p].VALID_LIFETIME = self.VALID_LIFETIME
            if self.PREFIXES[p].PREFERRED_LIFETIME == 0:
                self.PREFIXES[p].PREFERRED_LIFETIME = self.PREFERRED_LIFETIME
            # normalize ranges
            self.PREFIXES[p].RANGE = self.PREFIXES[p].RANGE.lower()
            # route via Link Local Address
            self.PREFIXES[p].ROUTE_LINK_LOCAL = BOOLPOOL[self.PREFIXES[p].ROUTE_LINK_LOCAL]
            # add prototype for later fast validity comparison of rebinding leases
            # also use as proof of validity of address patterns
            self.PREFIXES[p].build_prototype()

        # check if some options are set by cli options
        if self.cli_user is not None:
            self.USER = self.cli_user
        if not self.cli_group is None:
            self.GROUP = self.cli_group
        if not self.cli_duid is None:
            self.SERVERDUID = self.cli_duid
        if not self.cli_really_do_it is None:
            self.REALLY_DO_IT = BOOLPOOL[self.cli_really_do_it.lower()]

        # check config
        msg_prefix = 'General configuration:'

        # check user and group
        try:
            pwd.getpwnam(self.USER)
        except:
            error_exit(f"{msg_prefix} User '{self.USER}' does not exist")
        try:
            grp.getgrnam(self.GROUP)
        except:
            error_exit(f"{msg_prefix} Group '{self.GROUP}' does not exist")

        # check interface
        if not self.IGNORE_INTERFACE:
            for i in self.INTERFACE:
                # also accept Linux VLAN and other definitions but interface must exist
                if not i in get_interfaces() or not re.match('^[a-z0-9_:.%-]*$', i, re.IGNORECASE):
                    error_exit(f"{msg_prefix} Interface '{i}' is unknown.")

        # check multicast address
        try:
            decompress_ip6(self.MCAST)
        except Exception as err:
            error_exit(f"{msg_prefix} Multicast address '{err}' is invalid.")
        if not self.MCAST.lower().startswith('ff'):
            error_exit(f"Multicast address '{msg_prefix}' is invalid.")

        # check DHCPv6 port
        if not self.PORT.isdigit():
            error_exit(f"{msg_prefix} Port '{self.PORT}' is invalid")
        elif not 0 < int(self.PORT) <= 65535:
            error_exit(f"{msg_prefix} Port '{self.PORT}' is invalid")

        # check server's address
        try:
            decompress_ip6(self.ADDRESS)
        except Exception as err:
            error_exit(f"{msg_prefix} Server address '{err}' is invalid.")

        # check server duid
        if not self.SERVERDUID.isalnum():
            error_exit(f"{msg_prefix} Server DUID '{self.SERVERDUID}' must be alphanumeric.")

        # check nameserver to be given to client
        for nameserver in self.NAMESERVER:
            try:
                decompress_ip6(nameserver)
            except Exception as err:
                error_exit(f"{msg_prefix} Name server address '{err}' is invalid.")

        # split NTP server types into possible 3 (address, multicast, FQDN)
        # more details about this madness are available at https://tools.ietf.org/html/rfc5908
        for ntp_server in self.NTP_SERVER:
            try:
                decompress_ip6(ntp_server)
                # if decompressing worked it must be an address
                if ntp_server.lower().startswith('ff'):
                    self.NTP_SERVER_DICT['MC'].append(ntp_server.lower())
                else:
                    self.NTP_SERVER_DICT['SRV'].append(ntp_server.lower())
            except Exception as err:
                if re.match('^[a-z0-9.-]*$', ntp_server, re.IGNORECASE):
                    self.NTP_SERVER_DICT['FQDN'].append(ntp_server.lower())
                else:
                    error_exit(f"{msg_prefix} NTP server address '{ntp_server}' is invalid.")

        # partly check of domain name validity
        if not re.match('^[a-z0-9.-]*$', self.DOMAIN, re.IGNORECASE):
            error_exit(f"{msg_prefix} Domain name '{self.DOMAIN}' is invalid.")

        # partly check of domain name validity
        if not self.DOMAIN.lower()[0].isalpha() or \
                not self.DOMAIN.lower()[-1].isalpha():
            error_exit(f"{msg_prefix} Domain name '{self.DOMAIN}' is invalid.")

        # check domain search list domains
        for d in self.DOMAIN_SEARCH_LIST:
            # partly check of domain name validity
            if not re.match('^[a-z0-9.-]*$', d, re.IGNORECASE):
                error_exit(f"{msg_prefix} Domain search list domain name '{d}' is invalid.")

            # partly check of domain name validity
            if not d.lower()[0].isalpha() or \
                    not d.lower()[-1].isalpha():
                error_exit(f"{msg_prefix} Domain search list domain name '{d}' is invalid.")

        # check if valid lifetime is a number
        if not self.VALID_LIFETIME.isdigit():
            error_exit(f"{msg_prefix} Valid lifetime '{self.VALID_LIFETIME}' is invalid.")

        # check if preferred lifetime is a number
        if not self.PREFERRED_LIFETIME.isdigit():
            error_exit(f"{msg_prefix} Preferred lifetime '{self.PREFERRED_LIFETIME}' is invalid.")

        # check if valid lifetime is longer than preferred lifetime
        if not int(self.VALID_LIFETIME) > int(self.PREFERRED_LIFETIME):
            error_exit(f"{msg_prefix} Valid lifetime '{self.VALID_LIFETIME}' is shorter "
                       f"than preferred lifetime '{self.PREFERRED_LIFETIME}' and thus invalid.")

        # check if T1 is a number
        if not self.T1.isdigit():
            error_exit(f"{msg_prefix} T1 '{self.T1}' is invalid.")

        # check if T2 is a number
        if not self.T2.isdigit():
            error_exit(f"{msg_prefix} T2 '{self.T2}' is invalid.")

        # check T2 is not smaller than T1
        if not int(self.T2) >= int(self.T1):
            error_exit(f"{msg_prefix} T2 '{self.T2}' is shorter than T1 '{self.T1}' and thus invalid.")

        # check if T1 <= T2 <= PREFERRED_LIFETIME <= VALID_LIFETIME
        if not (int(self.T1) <= int(self.T2) <= int(self.PREFERRED_LIFETIME) <= int(self.VALID_LIFETIME)):
            error_exit(f"{msg_prefix} Time intervals T1 '{self.T1}' <= T2 '{self.T2}' <= "
                       f"preferred_lifetime '{self.PREFERRED_LIFETIME}' <= "
                       f"valid_lifetime '{self.VALID_LIFETIME}' are wrong.")

        # check server preference
        if not self.SERVER_PREFERENCE.isdigit():
            error_exit(f"{msg_prefix} Server preference '{self.SERVER_PREFERENCE}' is invalid.")
        elif not 0 <= int(self.SERVER_PREFERENCE) <= 255:
            error_exit(f"Server preference '{self.SERVER_PREFERENCE}' is invalid")

        # check information refresh time
        if not self.INFORMATION_REFRESH_TIME.isdigit():
            error_exit(f"{msg_prefix} Information refresh time '{self.INFORMATION_REFRESH_TIME}' is invalid.")
        elif not 0 < int(self.INFORMATION_REFRESH_TIME):
            error_exit(f"{msg_prefix} Information refresh time preference "
                       f"'{self.INFORMATION_REFRESH_TIME}' is pretty short.")

        # check validity of configuration source
        if self.STORE_CONFIG not in ['mysql', 'postgresql', 'sqlite', 'file', False]:
            error_exit(f"{msg_prefix} Unknown config storage type '{self.STORAGE}' is invalid.")

        # check which type of storage to use for leases
        if self.STORE_VOLATILE not in ['mysql', 'postgresql', 'sqlite']:
            error_exit(f"{msg_prefix} Unknown volatile storage type '{self.VOLATILE}' is invalid.")

        # check if database for config and volatile is equal - if any
        if self.STORE_CONFIG in ['mysql', 'postgresql'] and self.STORE_VOLATILE in ['mysql', 'postgresql']:
            if self.STORE_CONFIG != self.STORE_VOLATILE:
                error_exit(f"{msg_prefix} Storage types for database access have to be equal - "
                           f"'{self.STORE_CONFIG}' != '{self.STORE_VOLATILE}'.")

        # check validity of config file
        if self.STORE_CONFIG == 'file':
            if os.path.exists(self.STORE_FILE_CONFIG):
                if not (os.path.isfile(self.STORE_FILE_CONFIG) or
                        os.path.islink(self.STORE_FILE_CONFIG)):
                    error_exit(f"{msg_prefix} Config file '{self.STORE_FILE_CONFIG}' is no file or link.")
            else:
                error_exit(f"{msg_prefix} Config file '{self.STORE_FILE_CONFIG}' does not exist.")

        # check validity of config db sqlite file
        if self.STORE_CONFIG == 'sqlite':
            if os.path.exists(self.STORE_SQLITE_CONFIG):
                if not (os.path.isfile(self.STORE_SQLITE_CONFIG) or
                        os.path.islink(self.STORE_SQLITE_CONFIG)):
                    error_exit(f"{msg_prefix} SQLite file '{self.STORE_SQLITE_CONFIG}' is no file or link.")
            else:
                error_exit(f"{msg_prefix} SQLite file '{self.STORE_SQLITE_CONFIG}' does not exist.")

        # check validity of volatile db sqlite file
        if self.STORE_VOLATILE == 'sqlite':
            if os.path.exists(self.STORE_SQLITE_VOLATILE):
                if not (os.path.isfile(self.STORE_SQLITE_VOLATILE) or
                        os.path.islink(self.STORE_SQLITE_VOLATILE)):
                    error_exit(f"{msg_prefix} SQLite file '{self.STORE_SQLITE_VOLATILE}' is no file or link.")
            else:
                error_exit(f"{msg_prefix} SQLite file '{self.STORE_SQLITE_VOLATILE}' does not exist.")

        # check log validity
        if self.LOG:
            if self.LOG_FILE != '':
                if os.path.exists(self.LOG_FILE):
                    if not (os.path.isfile(self.LOG_FILE) or
                            os.path.islink(self.LOG_FILE)):
                        error_exit(f"{msg_prefix} Logfile '{self.LOG_FILE}' is no file or link.")
                else:
                    error_exit(f"{msg_prefix} Logfile '{self.LOG_FILE}' does not exist.")
                # check ownership of logfile
                stat_result = os.stat(self.LOG_FILE)
                if not stat_result.st_uid == pwd.getpwnam(self.USER).pw_uid:
                    error_exit(f"{msg_prefix} User {self.USER} is not owner of logfile '{self.LOG_FILE}'.")
                if not stat_result.st_gid == grp.getgrnam(self.GROUP).gr_gid:
                    error_exit(f"{msg_prefix} Group {self.GROUP} is not owner of logfile '{self.LOG_FILE}'.")
            else:
                error_exit(f'{msg_prefix} No logfile configured.')

            if self.LOG_LEVEL not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
                error_exit(f"Log level '{self.LOG_LEVEL}' is invalid")
            if self.LOG_SYSLOG:
                if self.LOG_SYSLOG_FACILITY not in ['KERN', 'USER', 'MAIL', 'DAEMON', 'AUTH',
                                                    'LPR', 'NEWS', 'UUCP', 'CRON', 'SYSLOG',
                                                    'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3',
                                                    'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7']:
                    error_exit(f"{msg_prefix} Syslog facility '{self.LOG_SYSLOG_FACILITY}' is invalid.")

                if self.LOG_SYSLOG_DESTINATION.startswith('/'):
                    stat_result = os.stat(self.LOG_SYSLOG_DESTINATION)
                    if not stat.S_ISSOCK(stat_result.st_mode):
                        error_exit(
                            f"{msg_prefix} Syslog destination '{self.LOG_SYSLOG_DESTINATION}' is no socket.")
                elif self.LOG_SYSLOG_DESTINATION.count(':') > 0:
                    if self.LOG_SYSLOG_DESTINATION.count(':') > 1:
                        error_exit(f"{msg_prefix} Syslog destination '{self.LOG_SYSLOG_DESTINATION}' "
                                   f"is no valid host:port destination.")

        # check authentification information
        if not self.AUTHENTICATION_INFORMATION.isalnum():
            error_exit(f"{msg_prefix} Authentification information '{self.AUTHENTICATION_INFORMATION}' "
                       f"must be alphanumeric.")

        # check validity of identification attributes
        for i in self.IDENTIFICATION:
            if i not in ['mac', 'hostname', 'duid']:
                error_exit(f"{msg_prefix} Identification must consist of 'mac', 'hostname' and/or 'duid'.")

        # check validity of identification mode
        if self.IDENTIFICATION_MODE.strip() not in ['match_all', 'match_some']:
            error_exit(f"{msg_prefix} Identification mode must be one of 'match_all' or 'match_some'.")

        # check if request rate limit seconds are a number
        if not self.REQUEST_LIMIT_TIME.isdigit():
            error_exit(f"{msg_prefix} Request limit time '{self.REQUEST_LIMIT_TIME}' is invalid.")

        # check if request rate limit count is a number
        if not self.REQUEST_LIMIT_COUNT.isdigit():
            error_exit(f"{msg_prefix} Request limit count '{self.REQUEST_LIMIT_COUNT}' is invalid.")

        # check if request rate limit blacklist release time seconds are a number
        if not self.REQUEST_LIMIT_RELEASE_TIME.isdigit():
            error_exit(f"{msg_prefix} Request limit blacklist release time "
                       f"'{self.REQUEST_LIMIT_RELEASE_TIME}' is invalid.")

        # check validity of identification attributes
        if self.REQUEST_LIMIT_IDENTIFICATION not in ['mac', 'llip']:
            error_exit(f"{msg_prefix} Request limit identification must be one of 'mac' or 'llip'.")

        # Make integers of number strings to avoid later repeated conversion
        # more to come...
        self.REQUEST_LIMIT_TIME = int(self.REQUEST_LIMIT_TIME)
        self.REQUEST_LIMIT_COUNT = int(self.REQUEST_LIMIT_COUNT)
        self.REQUEST_LIMIT_RELEASE_TIME = int(self.REQUEST_LIMIT_RELEASE_TIME)

        # cruise through classes
        # more checks to come...
        for c in self.CLASSES:
            msg_prefix = f"Class '{c}':"
            if self.CLASSES[c].ANSWER not in ['normal',
                                              'noaddress',
                                              'none']:
                error_exit(f"{msg_prefix} answer type must be one of 'normal', 'noaddress' and 'none'.")

            # check interface
            if not self.IGNORE_INTERFACE:
                for i in self.CLASSES[c].INTERFACE:
                    # also accept Linux VLAN and other definitions but interface must exist
                    if i not in get_interfaces() or not re.match('^[a-z0-9_:.%-]*$', i, re.IGNORECASE):
                        error_exit(f"{msg_prefix} Interface '{i}' is invalid.")

            # check advertised IA types
            for i in self.CLASSES[c].ADVERTISE:
                if i not in ['addresses', 'prefixes']:
                    error_exit("Only 'addresses' and 'prefixes' can be advertised.")

            # check nameserver to be given to client
            for nameserver in self.CLASSES[c].NAMESERVER:
                try:
                    decompress_ip6(nameserver)
                except Exception as err:
                    error_exit(f"{msg_prefix} Name server address '{err}' is invalid.")

            # split NTP server types into possible 3 (address, multicast, FQDN)
            # more details about this madness are available at https://tools.ietf.org/html/rfc5908
            for ntp_server in self.CLASSES[c].NTP_SERVER:
                try:
                    decompress_ip6(ntp_server)
                    # if decompressing worked it must be an address
                    if ntp_server.lower().startswith('ff'):
                        self.CLASSES[c].NTP_SERVER_dict['MC'].append(ntp_server.lower())
                    else:
                        self.CLASSES[c].NTP_SERVER_dict['SRV'].append(ntp_server.lower())
                except Exception as err:
                    if re.match('^[a-z0-9.-]*$', ntp_server, re.IGNORECASE):
                        self.CLASSES[c].NTP_SERVER_dict['FQDN'].append(ntp_server.lower())
                    else:
                        error_exit(f"{msg_prefix} NTP server address '{ntp_server}' is invalid.")

            # check if T1 is a number
            if not self.CLASSES[c].T1.isdigit():
                error_exit(f"{msg_prefix} T1 '{self.CLASSES[c].T1}' is invalid.")

            # check if T2 is a number
            if not self.CLASSES[c].T2.isdigit():
                error_exit(f"{msg_prefix} T2 '{self.CLASSES[c].T2}' is invalid.")

            # check T2 is not smaller than T1
            if not int(self.CLASSES[c].T2) >= int(self.CLASSES[c].T1):
                error_exit(f"{msg_prefix} T2 '{self.CLASSES[c].T2}' is shorter "
                           f"than T1 '{self.CLASSES[c].T1}' and thus invalid.")

            # check every single address of a class
            for a in self.CLASSES[c].ADDRESSES:
                msg_prefix = f"Class '{c}' Address type '{a}':"
                # test if used addresses are defined
                if a not in self.ADDRESSES:
                    error_exit(f"{msg_prefix} Address type '{a}' is not defined.")

                # test validity of category
                if self.ADDRESSES[a].CATEGORY.strip() not in ['eui64', 'fixed', 'range', 'random', 'mac', 'id', 'dns']:
                    error_exit(f"{msg_prefix} Category '{self.ADDRESSES[a].CATEGORY}' is invalid. "
                               f"Category must be one of 'eui64', 'fixed', 'range', 'random', 'mac', 'id' and 'dns'.")

                # test validity of pattern - has its own error output
                self.ADDRESSES[a].build_prototype()
                # test existence of category specific variable in pattern
                if self.ADDRESSES[a].CATEGORY == 'range':
                    if not re.match('^[0-9a-f]{1,4}-[0-9a-f]{1,4}$', self.ADDRESSES[a].RANGE, re.IGNORECASE):
                        error_exit(f"{msg_prefix} Range '{self.ADDRESSES[a].RANGE}' is not valid.")
                    if not 0 < self.ADDRESSES[a].PATTERN.count('$range$') < 2:
                        error_exit(f"{msg_prefix} Pattern '{self.ADDRESSES[a].PATTERN.strip()}' contains wrong "
                                   f"number of '$range$' variables for category 'range'.")
                    elif not self.ADDRESSES[a].PATTERN.endswith('$range$'):
                        error_exit(f"{msg_prefix} Pattern '{self.ADDRESSES[a].PATTERN.strip()}' must end "
                                   f"with '$range$' variable for category 'range'.")

                if self.ADDRESSES[a].CATEGORY == 'mac':
                    if not 0 < self.ADDRESSES[a].PATTERN.count('$mac$') < 2:
                        error_exit(f"{msg_prefix} Pattern '{self.ADDRESSES[a].PATTERN.strip()}' contains wrong "
                                   f"number of '$mac$' variables for category 'mac'.")

                if self.ADDRESSES[a].CATEGORY == 'id':
                    if not self.ADDRESSES[a].PATTERN.count('$id$') == 1:
                        error_exit(f"{msg_prefix} Pattern '{self.ADDRESSES[a].PATTERN.strip()}' contains wrong "
                                   f"number of '$id$' variables for category 'id'.")

                if self.ADDRESSES[a].CATEGORY == 'random':
                    if not self.ADDRESSES[a].PATTERN.count('$random64$') == 1:
                        error_exit(f"{msg_prefix} Pattern '{self.ADDRESSES[a].PATTERN.strip()}' contains wrong "
                                   f"number of '$random64$' variables for category 'random'.")

                if self.ADDRESSES[a].CATEGORY == 'dns':
                    if not len(self.NAMESERVER) > 0:
                        error_exit("Address of category 'dns' needs a set nameserver.")

                # check ia_type
                if not self.ADDRESSES[a].IA_TYPE.strip().lower() in ['na', 'ta']:
                    error_exit(f"{msg_prefix}: IA type '{self.ADDRESSES[a].IA_TYPE.strip()}' "
                               f"must be one of 'na' or 'ta'.")

                # check if valid lifetime is a number
                if not self.ADDRESSES[a].VALID_LIFETIME.isdigit():
                    error_exit(f"{msg_prefix} Valid lifetime '{self.ADDRESSES[a].VALID_LIFETIME}' is invalid.")

                # check if preferred lifetime is a number
                if not self.ADDRESSES[a].PREFERRED_LIFETIME.isdigit():
                    error_exit(
                        f"{msg_prefix} Preferred lifetime '{self.ADDRESSES[a].PREFERRED_LIFETIME}' is invalid.")

                # check if valid lifetime is longer than preferred lifetime
                if not int(self.ADDRESSES[a].VALID_LIFETIME) >= int(self.ADDRESSES[a].PREFERRED_LIFETIME):
                    error_exit(f"{msg_prefix} Valid lifetime '{self.ADDRESSES[a].VALID_LIFETIME}' is shorter "
                               f"than preferred lifetime '{self.ADDRESSES[a].PREFERRED_LIFETIME}' and thus invalid.")

                # check if T1 <= T2 <= PREFERRED_LIFETIME <= VALID_LIFETIME
                if not (int(self.CLASSES[c].T1) <= int(self.CLASSES[c].T2) <=
                        int(self.ADDRESSES[a].PREFERRED_LIFETIME) <= int(self.ADDRESSES[a].VALID_LIFETIME)):
                    error_exit(f"{msg_prefix} Time intervals T1 '{self.CLASSES[c].T1}' <= "
                               f"T2 '{self.CLASSES[c].T2}' <= "
                               f"preferred_lifetime '{self.ADDRESSES[a].PREFERRED_LIFETIME}' <= "
                               f"valid_lifetime '{self.ADDRESSES[a].VALID_LIFETIME}' are wrong.")

            # check every single bootfile of a class
            for b in self.CLASSES[c].BOOTFILES:
                msg_prefix = f"Bootfile '{c}' BOOTFILE type '{b}':"
                # test if used bootfiles are defined
                if b not in self.BOOTFILES:
                    error_exit(f"{msg_prefix} Bootfile type '{b}' is not defined.")

            # check every single prefix of a class
            for p in self.CLASSES[c].PREFIXES:
                msg_prefix = f"Class '{c}' PREFIX type '{p}':"
                # test if used addresses are defined
                if p not in self.PREFIXES:
                    error_exit(f"{msg_prefix} Prefix type '{p}' is not defined.")

                # test validity of category
                if self.PREFIXES[p].CATEGORY.strip() not in ['range', 'id']:
                    error_exit(f"{msg_prefix} Category 'self.PREFIXES[p].CATEGORY' is invalid. "
                               f"Category must be 'range' or 'id'.")

                # test validity of pattern - has its own error output
                self.PREFIXES[p].build_prototype()
                # test existence of category specific variable in pattern
                if self.PREFIXES[p].CATEGORY == 'range':
                    if not re.match('^[0-9a-f]{1,4}-[0-9a-f]{1,4}$', self.PREFIXES[p].RANGE, re.IGNORECASE):
                        error_exit(f"{msg_prefix} Range '{self.PREFIXES[p].RANGE}' is not valid.")
                    if not 0 < self.PREFIXES[p].PATTERN.count('$range$') < 2:
                        error_exit(f"{msg_prefix} Pattern '{self.PREFIXES[p].PATTERN.strip()}' contains wrong "
                                   f"number of '$range$' variables for category 'range'.")
                    elif self.PREFIXES[p].PATTERN.endswith('$range$'):
                        error_exit(f"{msg_prefix} Pattern '{self.PREFIXES[p].PATTERN.strip()}' must not end "
                                   f"with '$range$' variable for category 'range'.")

                # check if valid lifetime is a number
                if not self.PREFIXES[p].VALID_LIFETIME.isdigit():
                    error_exit(f"{msg_prefix} Valid lifetime '{self.PREFIXES[p].VALID_LIFETIME}' is invalid.")

                # check if preferred lifetime is a number
                if not self.PREFIXES[p].PREFERRED_LIFETIME.isdigit():
                    error_exit(
                        f"{msg_prefix} Preferred lifetime '{self.PREFIXES[p].PREFERRED_LIFETIME}' is invalid.")

                # check if valid lifetime is longer than preferred lifetime
                if not int(self.PREFIXES[p].VALID_LIFETIME) >= int(self.PREFIXES[p].PREFERRED_LIFETIME):
                    error_exit(f"{msg_prefix} Valid lifetime '{self.PREFIXES[p].VALID_LIFETIME}' is shorter "
                               f"than preferred lifetime '{self.PREFIXES[p].PREFERRED_LIFETIME}' and thus invalid.")

                # check if T1 <= T2 <= PREFERRED_LIFETIME <= VALID_LIFETIME
                if not (int(self.CLASSES[c].T1) <= int(self.CLASSES[c].T2) <=
                        int(self.PREFIXES[p].PREFERRED_LIFETIME) <= int(self.PREFIXES[p].VALID_LIFETIME)):
                    error_exit(f"{msg_prefix} Time intervals T1 '{self.CLASSES[c].T1}' <= "
                               f"T2 '{self.CLASSES[c].T2}' <= "
                               f"preferred_lifetime '{self.PREFIXES[p].PREFERRED_LIFETIME}' <= "
                               f"valid_lifetime '{self.PREFIXES[p].VALID_LIFETIME}' are wrong.")

                # check if prefix is a valid number
                if not self.PREFIXES[p].LENGTH.isdigit():
                    error_exit(f"{msg_prefix} Prefix length '{self.PREFIXES[p].LENGTH}' is invalid.")
                if not 0 <= int(self.PREFIXES[p].LENGTH) <= 128:
                    error_exit(f"{msg_prefix} Prefix length '{self.PREFIXES[p].LENGTH}' must be in range 0-128.")

        # cruise through bootfiles
        # more checks to come...
        for b in self.BOOTFILES:
            msg_prefix = f"Bootfile '{b}':"
            bootfile_url = self.BOOTFILES[b].BOOTFILE_URL

            if bootfile_url is None or bootfile_url == '':
                error_exit(f"{msg_prefix} Bootfile url parameter must be set and is not allowed to be empty.")


class ConfigObject:
    """
        class providing methods both for addresses and prefixes
    """

    def build_prototype(self, pattern=None):
        """
            build prototype of pattern for later comparison with leases
        """

        # if called with de-$prefix$-ed pattern use it
        if pattern is None:
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
                prototype = prototype.replace('$mac$', 'xxxx:xxxx:xxxx')
            elif self.CATEGORY == 'id':
                prototype = prototype.replace('$id$', 'xxxx')
            elif self.CATEGORY == 'random':
                prototype = prototype.replace('$random64$', 'xxxx:xxxx:xxxx:xxxx')
            elif self.CATEGORY == 'range':
                prototype = prototype.replace('$range$', 'xxxx')
            try:
                # build complete 'address' and ignore all the Xs (strict=False)
                # all X will become x
                prototype = decompress_ip6(prototype, strict=False)
            except Exception as err:
                error_exit(f"Address type '{self.TYPE}' address pattern '{self.PATTERN}' is not valid: {err}")

        self.PROTOTYPE = prototype

    def inject_dynamic_prefix_into_prototype(self, dynamic_prefix):
        """
            called from main to put then known dynamic prefix into protoype
        """
        if '$prefix$' in self.PATTERN:
            prefix_pattern = self.PATTERN.replace('$prefix$', dynamic_prefix)
            self.build_prototype(prefix_pattern)

    def matches_prototype(self, address):
        """
            test if given address matches prototype and therefore this address' DNS zone
            information might be used
            only used for address types, not client instances
        """
        match = False
        # compare all chars of address and prototype, if they do match or
        # prototype has placeholder X return finally True, otherwise stop
        # at the first difference and give back False
        for i in range(32):
            if self.PROTOTYPE[i] == address[i] or self.PROTOTYPE[i] == 'x':
                match = True
            else:
                match = False
                break
        return match


class Address(ConfigObject):
    """
        class for address definition, used for config
    """

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
        # because 'class' is a python keyword we use 'client_class' here
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


class Class:
    """
        class for class definition
    """

    def __init__(self, name=''):
        self.NAME = name
        self.ADDRESSES = list()
        self.PREFIXES = list()
        self.BOOTFILES = list()
        self.NAMESERVER = ''
        self.NTP_SERVER = ''
        # Auxiliary options, derived from self.NTP_SERVER
        self.NTP_SERVER_dict = {'SRV': [], 'MC': [], 'FQDN': []}
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
        # of hosts should get IPv6 addresses and others not. They will get a 'NoAddrsAvail' handler if this option
        # is set to 'noaddress' or no answer at all if set to 'none'
        self.ANSWER = 'normal'
        # which IA_* should this class supply - addresses, prefixes or both?
        # shouldn't be an empty list because in this case the class would not make sense at all
        # as default only addresses will be advertised
        self.ADVERTISE = ['addresses']
        # commands or scripts to be called for setting and removing routes for prefixes
        self.CALL_UP = ''
        self.CALL_DOWN = ''


class BootFile:
    """
        class for netboot defintion
    """

    def __init__(self, name=''):
        self.NAME = name
        # PXE client architecture (Option 61)
        self.CLIENT_ARCHITECTURE = ''
        # PXE bootfile URL (Option 59)
        self.BOOTFILE_URL = ''
        # User class (Option 15)
        self.USER_CLASS = ''


def generate_duid():
    """
    Creates a DUID for the server - needed if none exists or is given
    :return:
    """
    return f'00010001{int(time.time()):08x}{uuid.getnode():012x}'


# singleton-like central instance
cfg = Config()
