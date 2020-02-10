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

import socket
import struct

# DHCPv6
MESSAGE = {1: 'SOLICIT',
           2: 'ADVERTISE',
           3: 'REQUEST',
           4: 'CONFIRM',
           5: 'RENEW',
           6: 'REBIND',
           7: 'REPLY',
           8: 'RELEASE',
           9: 'DECLINE',
           10: 'RECONFIGURE',
           11: 'INFORMATION-REQUEST',
           12: 'RELAY-FORW',
           13: 'RELAY-REPL'}

# see http://www.iana.org/assignments/dhcpv6-parameters/
OPTION = {1: 'CLIENTID',
          2: 'SERVERID',
          3: 'IA_NA',
          4: 'IA_TA',
          5: 'IAADDR',
          6: 'ORO',
          7: 'PREFERENCE',
          8: 'ELAPSED_TIME',
          9: 'RELAY_MSG',
          11: 'AUTH',
          12: 'UNICAST',
          13: 'STATUS_CODE',
          14: 'RAPID_COMMIT',
          15: 'USER_CLASS',
          16: 'VENDOR_CLASS',
          17: 'VENDOR_OPTS',
          18: 'INTERFACE_ID',
          19: 'RECONF_MSG',
          20: 'RECONF_ACCEPT',
          21: 'SIP_SERVER_D',
          22: 'SIP_SERVER_A',
          23: 'DNS_SERVERS',
          24: 'DOMAIN_LIST',
          25: 'IA_PD',
          26: 'IAPREFIX',
          27: 'NIS_SERVERS',
          28: 'NISP_SERVERS',
          29: 'NIS_DOMAIN_NAME',
          30: 'NISP_DOMAIN_NAME',
          31: 'SNTP_SERVERS',
          32: 'INFORMATION_REFRESH_TIME',
          33: 'BCMCS_SERVER_D',
          34: 'BCMCS_SERVER_A',
          36: 'GEOCONF_CIVIC',
          37: 'REMOTE_ID',
          38: 'SUBSCRIBER_ID',
          39: 'CLIENT_FQDN',
          40: 'PANA_AGENT',
          41: 'NEW_POSIX_TIMEZONE',
          42: 'NEW_TZDB_TIMEZONE',
          43: 'ERO',
          44: 'LQ_QUERY',
          45: 'CLIENT_DATA',
          46: 'CLT_TIME',
          47: 'LQ_RELAY_DATA',
          48: 'LQ_CLIENT_LINK',
          49: 'MIP6_HNINF',
          50: 'MIP6_RELAY',
          51: 'V6_LOST',
          52: 'CAPWAP_AC_V6',
          53: 'RELAY_ID',
          54: 'IPv6_Address_MoS',
          55: 'Pv6_FQDN_MoS',
          56: 'NTP_SERVER',
          57: 'V6_ACCESS_DOMAIN',
          58: 'SIP_UA_CS_LIST',
          59: 'BOOTFILE_URL',
          60: 'OPT_BOOTFILE_PARAM',
          61: 'OPTION_CLIENT_ARCH_TYPE'
          }

STATUS = {0: 'Success',
          1: 'Failure',
          2: 'No Addresses available',
          3: 'No Binding',
          4: 'Prefix not appropriate for link',
          5: 'Use Multicast',
          6: 'No Prefix available'}

# see https://tools.ietf.org/html/rfc4578#section-2.1
ARCHITECTURE_TYPE = {0: 'Intel x86PC',
                     1: 'NEC / PC98',
                     2: 'EFI Itanium',
                     3: 'DEC Alpha',
                     4: 'Arc x86',
                     5: 'Intel Lean Client',
                     6: 'EFI IA32',
                     7: 'EFI BC',
                     8: 'EFI Xscale',
                     9: 'EFI x86 - 64'}

# used for NETLINK in get_neighbor_cache_linux() access by Github/vokac
RTM_NEWNEIGH = 28
RTM_DELNEIGH = 29
RTM_GETNEIGH = 30
NLM_F_REQUEST = 1
# Modifiers to GET request
NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200
NLM_F_DUMP = (NLM_F_ROOT | NLM_F_MATCH)
# NETLINK message is always the same except header seq
MSG = struct.pack('B', socket.AF_INET6)
# always the same length...
MSG_HEADER_LENGTH = 17
# ...type...
MSG_HEADER_TYPE = RTM_GETNEIGH
# ...flags.
MSG_HEADER_FLAGS = (NLM_F_REQUEST | NLM_F_DUMP)
NLMSG_NOOP = 0x1  # /* Nothing.             */
NLMSG_ERROR = 0x2  # /* Error                */
NLMSG_DONE = 0x3  # /* End of a dump        */
NLMSG_OVERRUN = 0x4  # /* Data lost            */

NUD_INCOMPLETE = 0x01
# state of peer
NUD_REACHABLE = 0x02
NUD_STALE = 0x04
NUD_DELAY = 0x08
NUD_PROBE = 0x10
NUD_FAILED = 0x20
NUD_NOARP = 0x40
NUD_PERMANENT = 0x80
NUD_NONE = 0x00

NDA = {
    0: 'NDA_UNSPEC',
    1: 'NDA_DST',
    2: 'NDA_LLADDR',
    3: 'NDA_CACHEINFO',
    4: 'NDA_PROBES',
    5: 'NDA_VLAN',
    6: 'NDA_PORT',
    7: 'NDA_VNI',
    8: 'NDA_IFINDEX',
}
NLMSG_ALIGNTO = 4
NLA_ALIGNTO = 4


# collect most constants in a class for easier handling by calling numeric values via class properties
# at the same time still available with integer keys and string values
class Constants:
    """
    contains various categories of constants
    """
    class Category:
        """
        category containing constants
        'reverting' the dictionary because in certain parts for example the number of an option is referred to by
        its name as property
        """
        def __init__(self, category):
            for key, value in category.items():
                self.__dict__[value.replace('-', '_').replace(' ', '_').replace('/', 'or').upper()] = key

        def keys(self):
            # return key
            return self.__dict__.keys()

    def __init__(self):
        self.MESSAGE = self.Category(MESSAGE)
        self.STATUS = self.Category(STATUS)
        self.OPTION = self.Category(OPTION)
        # needed for logging - use original dict
        self.MESSAGE_DICT = MESSAGE
        # architecture types as dict
        self.ARCHITECTURE_TYPE_DICT = ARCHITECTURE_TYPE


# Add constants for global access
CONST = Constants()
