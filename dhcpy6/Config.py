# encoding: utf8
#
# config
#

import sys 
import ConfigParser
import stat
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

from Helpers import *

# use ctypes for libc access in GetLibC from Helpers
LIBC = GetLibC()

# needed for boolean options
BOOLPOOL = {"0":False, "1":True, "no":False, "yes":True, "false":False, "true":True, False:False, True:True, "on":True, "off":False}

# whitespace for options with more than one value
WHITESPACE = " ,"

# default usage text - to be extended
USAGE = """
dhcpy6d - DHCPv6 server

Usage: dhcpy6d --config <file> [--user <user>] [--group <group>] [--duid <duid>] [--really-do-it <yes>|<no>]
       dhcpy6d --generate-duid

See manpage dhcpy6d(8) for details.
"""


def GenerateDUID():
    return "00010001%08x%012x" % (time.time(), uuid.getnode())


class Config(object):
    """
      general settings  
    """           
    def _check_config(self):
        """
        checks validity of config settings
        """
        msg_prefix = "General configuration:"

        # check user and group
        try:
            pwd.getpwnam(self.USER)
        except:
             ErrorExit("%s User '%s' does not exist" % (msg_prefix, self.USER))
        try:
            grp.getgrnam(self.GROUP)
        except:
             ErrorExit("%s Group '%s' does not exist" % (msg_prefix, self.GROUP))
        
        # check interface
        for i in self.INTERFACE:
            # also accept Linux VLAN and other definitions but interface must exist
            if LIBC.if_nametoindex(i) == 0 or not re.match("^[a-z0-9_:%-]*$", i, re.IGNORECASE):
                ErrorExit("%s Interface '%s' is invalid." % (msg_prefix, i))
                
        # check multicast address
        try:
            DecompressIP6(self.MCAST)
        except Exception, err:
            ErrorExit("%s Multicast address '%s' is invalid." % (msg_prefix, err))
        if not self.MCAST.lower().startswith("ff"):    
            ErrorExit("Multicast address '%s' is invalid." % (msg_prefix))
        
        # check DHCPv6 port    
        if not self.PORT.isdigit():
            ErrorExit("%s Port '%s' is invalid" % (msg_prefix, self.PORT))
        elif not  0 < int(self.PORT) <= 65535:
            ErrorExit("%s Port '%s' is invalid" % (msg_prefix, self.PORT))
        
        # check server's address    
        try:
            DecompressIP6(self.ADDRESS)
        except Exception, err:
            ErrorExit("%s Server address '%s' is invalid." % (msg_prefix, err))
        
        # check server duid    
        if not self.SERVERDUID.isalnum():
            ErrorExit("%s Server DUID '%s' must be alphanumeric." % (msg_prefix, self.SERVERDUID))
        
        # check nameserver to be given to client
        for nameserver in self.NAMESERVER:
            try:
                DecompressIP6(nameserver)
            except Exception, err:
                ErrorExit("%s Name server address '%s' is invalid." % (msg_prefix, err))
        
        # partly check of domain name validity
        if not re.match("^[a-z0-9.-]*$", self.DOMAIN, re.IGNORECASE):
            ErrorExit("%s Domain name '%s' is invalid." % (msg_prefix, self.DOMAIN))
        
        # partly check of domain name validity         
        if not self.DOMAIN.lower()[0].isalpha() or \
           not self.DOMAIN.lower()[-1].isalpha():
                ErrorExit("%s Domain name '%s' is invalid." % (msg_prefix, self.DOMAIN))

        # check domain search list domains
        for d in self.DOMAIN_SEARCH_LIST:
            # partly check of domain name validity
            if not re.match("^[a-z0-9.-]*$", d, re.IGNORECASE):
                ErrorExit("%s Domain search list domain name '%s' is invalid." % (msg_prefix, d))

            # partly check of domain name validity
            if not d.lower()[0].isalpha() or \
               not d.lower()[-1].isalpha():
                    ErrorExit("%s Domain search list domain name '%s' is invalid." % (msg_prefix, d))

        # check if valid lifetime is a number    
        if not self.VALID_LIFETIME.isdigit():
            ErrorExit("%s Valid lifetime '%s' is invalid." % (msg_prefix, self.VALID_LIFETIME))
        
        # check if preferred lifetime is a number    
        if not self.PREFERRED_LIFETIME.isdigit():
            ErrorExit("%s Preferred lifetime '%s' is invalid." % (msg_prefix, self.PREFERRED_LIFETIME))
        
        # check if valid lifetime is longer than preferref lifetime    
        if not int(self.VALID_LIFETIME) > int(self.PREFERRED_LIFETIME):
            ErrorExit("%s Valid lifetime '%s' is shorter than preferred lifetime '%s' and thus invalid." %\
                      (msg_prefix, self.VALID_LIFETIME, self.PREFERRED_LIFETIME) )
            
        # check server preference    
        if not self.SERVER_PREFERENCE.isdigit():
            ErrorExit("%s Server preference '%s' is invalid." % (msg_prefix, self.SERVER_PREFERENCE))               
        elif not  0 <= int(self.SERVER_PREFERENCE) <= 255:
            ErrorExit("Server preference '%s' is invalid" % (self.SERVER_PREFERENCE))
        
        # check information refresh time
        if not self.INFORMATION_REFRESH_TIME.isdigit():
            ErrorExit("%s Information refresh time '%s' is invalid." % (msg_prefix, self.INFORMATION_REFRESH_TIME))
        elif not  0 < int(self.INFORMATION_REFRESH_TIME):
            ErrorExit("%s Information refresh time preference '%s' is pretty short." % (msg_prefix, self.INFORMATION_REFRESH_TIME))
        
        # check validity of configuration source    
        if not self.STORE_CONFIG in ["mysql", "sqlite", "file", False]:
            ErrorExit("%s Unknown config storage type '%s' is invalid." % (msg_prefix, self.STORAGE))
        
        # check which type of storage to use for leases
        if not self.STORE_VOLATILE in ["mysql", "sqlite"]:
            ErrorExit("%s Unknown volatile storage type '%s' is invalid." % (msg_prefix, self.VOLATILE))
        
        # check validity of config file
        if self.STORE_CONFIG == "file":
            if os.path.exists(self.STORE_FILE_CONFIG):
                if not (os.path.isfile(self.STORE_FILE_CONFIG) or
                   os.path.islink(self.STORE_FILE_CONFIG)):
                    ErrorExit("%s Config file '%s' is no file or link." % (msg_prefix, self.STORE_FILE_CONFIG))
            else:
                ErrorExit("%s Config file '%s' does not exist." % (msg_prefix, self.STORE_FILE_CONFIG))
        
        # check validity of config db sqlite file        
        if self.STORE_CONFIG == "sqlite":
            if os.path.exists(self.STORE_SQLITE_CONFIG):
                if not (os.path.isfile(self.STORE_SQLITE_CONFIG) or
                   os.path.islink(self.STORE_SQLITE_CONFIG)):
                    ErrorExit("%s SQLite file '%s' is no file or link." % (msg_prefix, self.STORE_SQLITE_CONFIG))
            else:
                ErrorExit("%s SQLite file '%s' does not exist." % (msg_prefix, self.STORE_SQLITE_CONFIG))
                
        # check validity of volatile db sqlite file        
        if self.STORE_VOLATILE == "sqlite":
            if os.path.exists(self.STORE_SQLITE_VOLATILE):
                if not (os.path.isfile(self.STORE_SQLITE_VOLATILE) or
                   os.path.islink(self.STORE_SQLITE_VOLATILE)):
                    ErrorExit("%s SQLite file '%s' is no file or link." % (msg_prefix, self.STORE_SQLITE_VOLATILE))
            else:
                ErrorExit("%s SQLite file '%s' does not exist." % (msg_prefix, self.STORE_SQLITE_VOLATILE))

        # check log validity    
        if self.LOG:
            if self.LOG_FILE != "":
                if os.path.exists(self.LOG_FILE):
                    if not (os.path.isfile(self.LOG_FILE) or
                       os.path.islink(self.LOG_FILE)):
                        ErrorExit("%s Logfile '%s' is no file or link." % (msg_prefix, self.LOG_FILE))
                else:
                    ErrorExit("%s Logfile '%s' does not exist." % (msg_prefix, self.LOG_FILE))
                # check ownership of logfile
                stat_result = os.stat(self.LOG_FILE)
                if not stat_result.st_uid == pwd.getpwnam(self.USER).pw_uid:
                    ErrorExit("%s User %s is not owner of logfile '%s'." % (msg_prefix, self.USER, self.LOG_FILE))
                if not stat_result.st_gid == grp.getgrnam(self.GROUP).gr_gid:
                    ErrorExit("%s Group %s is not owner of logfile '%s'." % (msg_prefix, self.GROUP, self.LOG_FILE))
            else:
                ErrorExit("%s No logfile configured." % (msg_prefix))

            if not self.LOG_LEVEL in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
                ErrorExit("Log level %s is invalid" % (self.LOG_LEVEL))
            if self.LOG_SYSLOG:
                if not self.LOG_SYSLOG_FACILITY in ["KERN", "USER", "MAIL", "DAEMON", "AUTH",
                                                     "LPR", "NEWS", "UUCP", "CRON", "SYSLOG",
                                                     "LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3",
                                                     "LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7"]:
                    ErrorExit("%s Syslog facility '%s' is invalid." % (msg_prefix, self.LOG_SYSLOG_FACILITY))

                if self.LOG_SYSLOG_DESTINATION.startswith("/"):
                    stat_result = os.stat(self.LOG_SYSLOG_DESTINATION)
                    if not stat.S_ISSOCK(stat_result.st_mode):
                        ErrorExit("%s Syslog destination '%s' is no socket." % (msg_prefix, self.LOG_SYSLOG_DESTINATION))
                elif self.LOG_SYSLOG_DESTINATION.count(":") > 0:
                    if self.LOG_SYSLOG_DESTINATION.count(":") > 1:
                        ErrorExit("%s Syslog destination '%s' is no valid host:port destination." % (msg_prefix, self.LOG_SYSLOG_DESTINATION))
                    
        # check authentification information    
        if not self.AUTHENTICATION_INFORMATION.isalnum():
            ErrorExit("%s Authentification information '%s' must be alphanumeric." % (msg_prefix, self.AUTHENTICATION_INFORMATION))
            
        # check validity of identification attributes    
        for i in self.IDENTIFICATION:
            if not i in ["mac", "hostname", "duid"]:
                ErrorExit("%s Identification must consist of 'mac', 'hostname' and/or 'duid'." % (msg_prefix))
        
        # check validity of identification mode
        if not self.IDENTIFICATION_MODE.strip() in ["match_all", "match_some"]:
            ErrorExit("%s Identification mode must be one of 'match_all' or 'macht_some'." % (msg_prefix))
        
        # cruise through classes    
        for c in self.CLASSES:
            for a in self.CLASSES[c].ADDRESSES:
                # test if used addresses are defined
                if not a in self.ADDRESSES:
                    ErrorExit("Class %s: Address type '%s' is not defined." % (c, a))
                # test validity of category
                if not self.ADDRESSES[a].CATEGORY.strip() in ["fixed", "range", "random", "mac", "id"]:
                    ErrorExit(" Address category '%s' is invalid. Category must be one of 'fixed', 'range', 'random' or 'mac'." % (a, self.ADDRESSES[a].CATEGORY))
                # test numberness and length of prefix
                if not self.ADDRESSES[a].PREFIX_LENGTH.strip().isdigit():
                    ErrorExit("Address type '%s': Prefix length '%s' is not a number." % (a, self.ADDRESSES[a].PREFIX_LENGTH.strip()))               
                elif not  0 <= int(self.ADDRESSES[a].PREFIX_LENGTH) <= 128:
                    ErrorExit("Address type '%s': Prefix length '%s' is out of range." % (a, self.ADDRESSES[a].PREFIX_LENGTH.strip())) 
                # test validity of pattern - has its own error output
                self.ADDRESSES[a]._build_prototype()
                # test existence of category specific variable in pattern
                if self.ADDRESSES[a].CATEGORY == "range":
                    if not 0 < self.ADDRESSES[a].PATTERN.count("$range$") < 2:
                        ErrorExit("Address type '%s': Pattern '%s' contains wrong number of '$range$' variables for category 'range'." % (a, self.ADDRESSES[a].PATTERN.strip())) 
                    elif not self.ADDRESSES[a].PATTERN.endswith("$range$"):
                        ErrorExit("Address type '%s': Pattern '%s' must end with '$range$' variable for category 'range'." % (a, self.ADDRESSES[a].PATTERN.strip())) 
                if self.ADDRESSES[a].CATEGORY == "mac":
                    if not 0 < self.ADDRESSES[a].PATTERN.count("$mac$") < 2:
                        ErrorExit("Address type '%s': Pattern '%s' contains wrong number of '$mac$' variables for category 'mac'." % (a, self.ADDRESSES[a].PATTERN.strip())) 
                if self.ADDRESSES[a].CATEGORY == "id":
                    if not 0 < self.ADDRESSES[a].PATTERN.count("$id$") < 2:
                        ErrorExit("Address type '%s': Pattern '%s' contains wrong number of '$id$' variables for category 'id'." % (a, self.ADDRESSES[a].PATTERN.strip())) 
                if self.ADDRESSES[a].CATEGORY == "random":
                    if not 0 < self.ADDRESSES[a].PATTERN.count("$random64$") < 2:
                        ErrorExit("Address type '%s': Pattern '%s' contains wrong number of '$random64$' variables for category 'random'." % (a, self.ADDRESSES[a].PATTERN.strip())) 
                # check ia_type
                
                if not self.ADDRESSES[a].IA_TYPE.strip().lower() in ["na", "ta"]:
                    ErrorExit("Address type '%s': IA type '%s' must be one of 'na' or 'ta'." % (a, self.ADDRESSES[a].IA_TYPE.strip())) 

    
    def __init__(self):
        """
            evaluate config file
        """
        # default settings
        # Server cfg.INTERFACE + addresses
        self.INTERFACE = "eth0"
        self.MCAST = "ff02::1:2"
        self.PORT = "547"
        self.ADDRESS = "2001:db8::1"
        # effective user and group - will have to be set mainly by distribution package
        self.USER = "root"
        self.GROUP = "root"
        # lets make the water turn black... or build a shiny server DUID
        # in case someone will ever debug something here: Wireshark shows
        # year 2042 even if it is 2012 - time itself is OK
        self.SERVERDUID = "00010001%08x%012x" % (time.time(), uuid.getnode())
        self.NAMESERVER = ""

        # domain for FQDN hostnames
        self.DOMAIN = "domain"
        # domain search list for option 24, according to RFC 3646
        # defaults to DOMAIN
        self.DOMAIN_SEARCH_LIST = ""

        # IA_NA Options
        # Default preferred lifetime for addresses
        self.PREFERRED_LIFETIME = "5400"
        # Default valid lifetime for addresses
        self.VALID_LIFETIME = "7200"
        # T1 RENEW
        self.T1 = "2700"
        # T2 REBIND
        self.T2 = "4050"
        
        # Server Preference
        self.SERVER_PREFERENCE = "255"

        # SNTP SERVERS Option 31
        self.SNTP_SERVERS = [ self.ADDRESS ]

        # INFORMATION REFRESH TIME option 32 for option 11 (INFORMATION REQUEST)
        # see RFC http://tools.ietf.org/html/rfc4242
        self.INFORMATION_REFRESH_TIME = "6000"    
        
        # config type
        # one of file, mysql, sqlite or none
        self.STORE_CONFIG = "none"
        # one of mysql or sqlite
        self.STORE_VOLATILE = "sqlite"

        # file for client information
        self.STORE_FILE_CONFIG = "clients.conf"
        
        # DB data
        self.STORE_MYSQL_HOST = "localhost"
        self.STORE_MYSQL_DB = "dhcpy6d"
        self.STORE_MYSQL_USER = "user"
        self.STORE_MYSQL_PASSWORD = "password"
        
        self.STORE_SQLITE_CONFIG = "config.sqlite"
        self.STORE_SQLITE_VOLATILE = "volatile.sqlite"

        # DNS Update settings
        self.DNS_UPDATE = "False"
        self.DNS_UPDATE_NAMESERVER = "::1"
        self.DNS_TTL = 86400
        self.DNS_RNDC_KEY = "rndc-key"
        self.DNS_RNDC_SECRET = "0000000000000000000000000000000000000000000000000000000000000"
        # DNS RFC 4704 client DNS wishes          
        # use client supplied hostname
        self.DNS_USE_CLIENT_HOSTNAME = "False"
        # ignore client ideas about DNS (if at all, what name to use, self-updating...) 
        self.DNS_IGNORE_CLIENT = "True"

        # Log ot not
        self.LOG = "False"
        # Log level
        self.LOG_LEVEL = "INFO"
        # Log on console
        self.LOG_CONSOLE = "False"
        # Logfile
        self.LOG_FILE = ""
        # Log to syslog
        self.LOG_SYSLOG = "False"
        # Syslog facility
        self.LOG_SYSLOG_FACILITY = "daemon"
        # Local syslog socket or server:port
        if platform.system() in ["Linux", "OpenBSD"]:
            self.LOG_SYSLOG_DESTINATION = "/dev/log"
        else:
            self.LOG_SYSLOG_DESTINATION = "/var/run/log"
        
        # some 128 bits
        self.AUTHENTICATION_INFORMATION = "00000000000000000000000000000000"
        
        # for debugging - if False nothing is done 
        self.REALLY_DO_IT = "True"
        
        # interval for TidyUp thread - time in seconds
        self.CLEANING_INTERVAL = 10
        
        # Address and class schemes
        self.ADDRESSES = dict()
        self.CLASSES = dict()
        
        self.IDENTIFICATION = "mac"
        self.IDENTIFICATION_MODE = "match_all"
        
        # regexp filters for hostnames etc.
        self.FILTERS = {"mac":[], "duid":[], "hostname":[]}
        
        # define a fallback default class and address scheme
        self.ADDRESSES["default"] = ConfigAddress(ia_type="na",
                                                   prefix_length="64",
                                                   category="mac",
                                                   pattern="fdef::$mac$",
                                                   aclass="default",
                                                   atype="default",
                                                   prototype="fdef0000000000000000XXXXXXXXXXXX")
        
        self.CLASSES["default"] = Class()
        self.CLASSES["default"].ADDRESSES.append("default")
        
        # define dummy address scheme for fixed addresses
        # pattern and prototype are not really needed as this
        # addresses are fixed
        self.ADDRESSES["fixed"] = ConfigAddress(ia_type="na",
                                                   prefix_length="64",
                                                   category="fixed",
                                                   pattern="fdef0000000000000000000000000001",
                                                   aclass="default",
                                                   atype="fixed",
                                                   prototype="fdef0000000000000000000000000000")              
        
        # config file from command line
        # default config file and cli values
        configfile = cli_options = cli_user = cli_group = cli_duid = cli_really_do_it = None
        # get multiple options
        try:
            cli_options, cli_remains = getopt.gnu_getopt(sys.argv[1:], "c:g:u:d:Gr:",
                                                                      ["config=",
                                                                       "user=",
                                                                       "group=",
                                                                       "duid=",
                                                                       "generate-duid",
                                                                       "really-do-it="])
            for opt, arg in cli_options:
                if opt in ("-c", "--config"):
                    configfile = arg
                if opt in ("-g", "--group"):
                    cli_group = arg
                if opt in ("-u", "--user"):
                    cli_user = arg
                if opt in ("-d", "--duid"):
                    cli_duid = arg
                if opt in ("-r", "--really-do-it"):
                    cli_really_do_it = arg
                if opt in ("-G", "--generate-duid"):
                    print GenerateDUID()
                    sys.exit(0)
        except getopt.GetoptError, err:
            print err
            print USAGE
            sys.exit(1)

        if configfile == None:
           ErrorExit("No config file given - please use --config <config.file>")

        if os.path.exists(configfile):
            if not (os.path.isfile(configfile) or
               os.path.islink(configfile)):
                ErrorExit("Configuration file '%s' is no file or link." % (configfile))
        else:
            ErrorExit("Configuration file '%s' does not exist." % (configfile))

        # instantiate Configparser 
        config = ConfigParser.ConfigParser()
        config.read(configfile)           
        
        # whyever sections classes get overwritten sometimes and so some configs had been missing
        # so create classes and addresses here
        for section in config.sections():
            if section.startswith("class_"):
                self.CLASSES[section.split("class_")[1]] = Class(name=section.split("class_")[1].strip())
            if section.startswith("address_"):
                self.ADDRESSES[section.split("address_")[1].strip()] = ConfigAddress()
        
        for section in config.sections():
            # go through all items
            for item in config.items(section):
                if section.upper() == "DHCPY6D":
                    # check if keyword is known - if not, exit
                    if not item[0].upper() in self.__dict__:
                        ErrorExit("Keyword '%s' in section '[%s]' of configuration file '%s' is unknown." % (item[0], section, configfile))
                    # ConfigParser seems to be not case sensitive so settings get normalized
                    object.__setattr__(self, item[0].upper(), str(item[1]).strip())
                else:
                    # global address schemes
                    if section.startswith("address_"):
                        # check if keyword is known - if not, exit
                        if not item[0].upper() in self.ADDRESSES[section.split("address_")[1]].__dict__:
                            ErrorExit("Keyword '%s' in section '[%s]' of configuration file '%s' is unknown." % (item[0], section, configfile))
                        self.ADDRESSES[section.split("address_")[1]].__setattr__(item[0].upper(), str(item[1]).strip())   
                                                            
                    # global classes with their addresses
                    elif section.startswith("class_"):
                        # check if keyword is known - if not, exit
                        if not item[0].upper() in self.CLASSES[section.split("class_")[1]].__dict__:
                            ErrorExit("Keyword '%s' in section '[%s]' of configuration file '%s' is unknown." % (item[0], section, configfile))
                        if item[0].upper() == "ADDRESSES":
                            # strip whitespace and separators of addresses
                            lex = shlex.shlex(item[1])
                            lex.whitespace = WHITESPACE
                            lex.wordchars += ":."
                            for address in lex:
                                if len(address) > 0:
                                    self.CLASSES[section.split("class_")[1]].ADDRESSES.append(address) 
                        else:
                            self.CLASSES[section.split("class_")[1]].__setattr__(item[0].upper(), str(item[1]).strip())

        # finetuning
        self.IDENTIFICATION = ListifyOption(self.IDENTIFICATION)

        # get interfaces as list
        self.INTERFACE = ListifyOption(self.INTERFACE)
        
        # create default classes for each interface - if not defined
        # derive from default "default" class
        for i in self.INTERFACE:
            if not "default_" + i in self.CLASSES:
                self.CLASSES["default_" + i] = copy.copy(self.CLASSES["default"])
                self.CLASSES["default_" + i].NAME = "default_" + i
                self.CLASSES["default_" + i].INTERFACE = i
        
        # lower storage
        self.STORE_CONFIG = self.STORE_CONFIG.lower()
        self.STORE_VOLATILE = self.STORE_VOLATILE.lower()
    
        # boolize none-config-store
        if self.STORE_CONFIG.lower() == "none":
            self.STORE_CONFIG = False

        # if no domain search list has been given use DOMAIN
        if len(self.DOMAIN_SEARCH_LIST) == 0:
            self.DOMAIN_SEARCH_LIST = self.DOMAIN

        # domain search list has to be a list
        self.DOMAIN_SEARCH_LIST = ListifyOption(self.DOMAIN_SEARCH_LIST)

        # get nameservers as list
        if len(self.NAMESERVER) > 0:
            self.NAMESERVER = ListifyOption(self.NAMESERVER)
        
        # convert to boolean value
        self.DNS_UPDATE = BOOLPOOL[self.DNS_UPDATE.lower()]
        self.DNS_USE_CLIENT_HOSTNAME = BOOLPOOL[self.DNS_USE_CLIENT_HOSTNAME.lower()]
        self.DNS_IGNORE_CLIENT = BOOLPOOL[self.DNS_IGNORE_CLIENT.lower()]
        self.REALLY_DO_IT = BOOLPOOL[self.REALLY_DO_IT.lower()]
        self.LOG = BOOLPOOL[self.LOG.lower()]
        self.LOG_CONSOLE = BOOLPOOL[self.LOG_CONSOLE.lower()]
        self.LOG_LEVEL = self.LOG_LEVEL.upper()        
        self.LOG_SYSLOG = BOOLPOOL[self.LOG_SYSLOG.lower()]
        self.LOG_SYSLOG_FACILITY = self.LOG_SYSLOG_FACILITY.upper()
        
        # index of classes which add some identification rules etc.
        for c in self.CLASSES.values():
            if c.FILTER_MAC != "": self.FILTERS["mac"].append(c)
            if c.FILTER_DUID != "": self.FILTERS["duid"].append(c)
            if c.FILTER_HOSTNAME != "": self.FILTERS["hostname"].append(c)
            if c.NAMESERVER != "": c.NAMESERVER = ListifyOption(c.NAMESERVER)
            if c.INTERFACE != "":
                c.INTERFACE = ListifyOption(c.INTERFACE)
            else:
                # use general setting if none specified
                c.INTERFACE = self.INTERFACE
            
            # use default T1 and T2 if not defined
            if c.T1 == 0: c.T1 = self.T1
            if c.T2 == 0: c.T2 = self.T2

        # set type properties for addresses
        for a in self.ADDRESSES:
            # name for address, important for leases db
            self.ADDRESSES[a].TYPE = a
            if self.ADDRESSES[a].VALID_LIFETIME == 0: self.ADDRESSES[a].VALID_LIFETIME = self.VALID_LIFETIME
            if self.ADDRESSES[a].PREFERRED_LIFETIME == 0: self.ADDRESSES[a].PREFERRED_LIFETIME = self.PREFERRED_LIFETIME
            # normalize ranges
            self.ADDRESSES[a].RANGE = self.ADDRESSES[a].RANGE.lower()
            # add prototype for later fast validity comparison of rebinding leases
            # also use as proof of validity of address patterns
            self.ADDRESSES[a]._build_prototype()
            # convert boolean string to boolean value
            self.ADDRESSES[a].DNS_UPDATE = BOOLPOOL[self.ADDRESSES[a].DNS_UPDATE]
            if self.ADDRESSES[a].DNS_ZONE == "": self.ADDRESSES[a].DNS_ZONE = self.DOMAIN
            if self.ADDRESSES[a].DNS_TTL == "0": self.ADDRESSES[a].DNS_TTL = self.DNS_TTL

        # check if some options are set by cli options
        if not cli_user == None:
            self.USER = cli_user
        if not cli_group == None:
            self.GROUP = cli_group
        if not cli_duid == None:
            self.SERVERDUID = cli_duid
        if not cli_really_do_it == None:
            self.REALLY_DO_IT =  BOOLPOOL[cli_really_do_it.lower()]
        # check config
        self._check_config()
                   
            
class ConfigAddress(object):
    """
    class for address definition, used for config
    """
    def __init__(self, address=None,
                 ia_type="na",
                 prefix_length="64",
                 category="random",
                 pattern="2001:db8::$random64$",
                 preferred_lifetime=0,
                 valid_lifetime=0,
                 atype="default",
                 aclass="default",
                 prototype="",
                 range="",
                 dns_update=False,
                 dns_zone="",
                 dns_rev_zone="0.8.b.d.1.0.0.2.ip6.arpa",
                 dns_ttl = "0",
                 valid = True):
        self.PREFIX_LENGTH = prefix_length
        self.CATEGORY = category
        self.PATTERN = pattern
        self.IA_TYPE = ia_type
        self.PREFERRED_LIFETIME = preferred_lifetime
        self.VALID_LIFETIME = valid_lifetime
        self.ADDRESS = address
        self.RANGE = range.lower()
        # because "class" is a python keyword we use "aclass" here
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
        
        
    def _build_prototype(self):
        """
        build prototype of pattern for later comparison with leases
        """
        a = self.PATTERN
        #a = a.replace("$prefix$", self.PREFIX)
        
        # check different client address categories - to be extended!
        if self.CATEGORY in ["mac", "id", "range", "random"]:
            if self.CATEGORY == "mac":
                a = a.replace("$mac$", "XXXX:XXXX:XXXX")
            elif self.CATEGORY == "id":
                a = a.replace("$id$", "XXXX")
            elif self.CATEGORY == "random":
                a = a.replace("$random64$", "XXXX:XXXX:XXXX:XXXX")
            elif self.CATEGORY == "range":
                a = a.replace("$range$", "XXXX")
            try:
                # build complete "address" and ignore all the Xs (strict=False)
                a = DecompressIP6(a, strict=False)
            except:
                #print "Address", self.TYPE + ": address pattern", self.PATTERN, "is not valid!"
                ErrorExit("Address type '%s' address pattern '%s' is not valid." % (self.TYPE, self.PATTERN))
            
        self.PROTOTYPE = a
        
    
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
            if  self.PROTOTYPE[i] == address[i] or self.PROTOTYPE[i] == "X":
                match = True
            else:
                match = False
                break
        return match
    

class ClientAddress(object):
    """
    class for address definition, used for clients
    """
    def __init__(self, address=None,
                 ia_type="na",
                 prefix_length="64",
                 category="random",
                 #pattern="2001:db8::$random64$",\
                 preferred_lifetime=0,
                 valid_lifetime=0,
                 atype="default",
                 aclass="default",
                 #prototype="",\
                 #range="",\
                 dns_update=False,
                 dns_zone="",
                 dns_rev_zone="0.8.b.d.1.0.0.2.ip6.arpa",
                 dns_ttl = "0",
                 valid = True,
                 ):
        self.PREFIX_LENGTH = prefix_length
        self.CATEGORY = category
        #self.PATTERN = pattern
        self.IA_TYPE = ia_type
        self.PREFERRED_LIFETIME = preferred_lifetime
        self.VALID_LIFETIME = valid_lifetime
        self.ADDRESS = address
        #self.RANGE = range.lower()
        # because "class" is a python keyword we use "aclass" here
        # this property stores the class the address is used for
        self.CLASS = aclass
        # same with type
        self.TYPE = atype
        # a prototypical address to be compared with leases given by
        # clients - if prototype and lease address kind of match
        # give back the lease as valid
        #self.PROTOTYPE = prototype
        # flag for updating address in DNS or not
        self.DNS_UPDATE = dns_update
        # DNS zone data
        self.DNS_ZONE = dns_zone.lower()
        self.DNS_REV_ZONE = dns_rev_zone.lower()
        self.DNS_TTL = dns_ttl
        # flag invalid addresses as invalid, valid ones as valid
        self.VALID = valid

            
class Class(object):
    """
    class for class definition
    """
    def __init__(self, name=""):
        self.NAME = name
        self.ADDRESSES = list()
        self.NAMESERVER = ""
        self.FILTER_MAC = ""
        self.FILTER_HOSTNAME = ""
        self.FILTER_DUID = ""
        self.IDENTIFICATION_MODE = "match_all"
        # RENEW time
        self.T1 = 0
        # REBIND time
        self.T2 = 0
        # at which interface this class of clients is served
        self.INTERFACE = ""
