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
MESSAGE_TYPES = {1: 'SOLICIT',
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

# response message_types hardcoded for better readability
MESSAGE_TYPE_ADVERTISE = 2
MESSAGE_TYPE_REPLY = 7

# DUID               
DUID_TYPES = {1: 'DUID-LLT',
              2: 'DUID-EN',
              3: 'DUID-LL',
              4: 'DUID-UUID'}

# see http://www.iana.org/assignments/dhcpv6-parameters/
OPTION_REQUEST = {1: 'OPTION_CLIENTID',
                  2: 'OPTION_SERVERID',
                  3: 'OPTION_IA_NA',
                  4: 'OPTION_IA_TA',
                  5: 'OPTION_IAADDR',
                  6: 'OPTION_ORO',
                  7: 'OPTION_PREFERENCE',
                  8: 'OPTION_ELAPSED_TIME',
                  9: 'OPTION_RELAY_MSG',
                  10: 'Unassigned',
                  11: 'OPTION_AUTH',
                  12: 'OPTION_UNICAST',
                  13: 'OPTION_STATUS_CODE',
                  14: 'OPTION_RAPID_COMMIT',
                  15: 'OPTION_USER_CLASS',
                  16: 'OPTION_VENDOR_CLASS',
                  17: 'OPTION_VENDOR_OPTS',
                  18: 'OPTION_INTERFACE_ID',
                  19: 'OPTION_RECONF_MSG',
                  20: 'OPTION_RECONF_ACCEPT',
                  21: 'SIP Servers Domain Name List',
                  22: 'SIP Servers IPv6 Address List',
                  23: 'DNS Recursive Name Server Option',
                  24: 'Domain Search List option',
                  25: 'OPTION_IA_PD',
                  26: 'OPTION_IAPREFIX',
                  27: 'OPTION_NIS_SERVERS',
                  28: 'OPTION_NISP_SERVERS',
                  29: 'OPTION_NIS_DOMAIN_NAME',
                  30: 'OPTION_NISP_DOMAIN_NAME',
                  31: 'OPTION_SNTP_SERVERS',
                  32: 'OPTION_INFORMATION_REFRESH_TIME',
                  33: 'OPTION_BCMCS_SERVER_D',
                  34: 'OPTION_BCMCS_SERVER_A',
                  35: 'Unassigned',
                  36: 'OPTION_GEOCONF_CIVIC',
                  37: 'OPTION_REMOTE_ID',
                  38: 'OPTION_SUBSCRIBER_ID',
                  39: 'OPTION_CLIENT_FQDN',
                  40: 'OPTION_PANA_AGENT',
                  41: 'OPTION_NEW_POSIX_TIMEZONE',
                  42: 'OPTION_NEW_TZDB_TIMEZONE',
                  43: 'OPTION_ERO',
                  44: 'OPTION_LQ_QUERY',
                  45: 'OPTION_CLIENT_DATA',
                  46: 'OPTION_CLT_TIME',
                  47: 'OPTION_LQ_RELAY_DATA',
                  48: 'OPTION_LQ_CLIENT_LINK',
                  49: 'OPTION_MIP6_HNINF',
                  50: 'OPTION_MIP6_RELAY',
                  51: 'OPTION_V6_LOST',
                  52: 'OPTION_CAPWAP_AC_V6',
                  53: 'OPTION_RELAY_ID',
                  54: 'OPTION-IPv6_Address-MoS',
                  55: 'OPTION-IPv6_FQDN-MoS'
                  }

STATUS_CODE = {0: 'Success',
               1: 'Failure',
               2: 'No Addresses available',
               3: 'No Binding',
               4: 'Prefix not appropriate for link',
               5: 'Use Multicast',
               6: 'No Prefix available'
               }

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
                     9: 'EFI x86 - 64'
                     }

# used for NETLINK in get_neighbor_cache_linux() access by Github/vokac
RTM_NEWNEIGH = 28
RTM_DELNEIGH = 29
RTM_GETNEIGH = 30
NLM_F_REQUEST = 1
# Modifiers to GET request
NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200
NLM_F_DUMP = (NLM_F_ROOT | NLM_F_MATCH)
# NETLINK message is alsways the same except header seq
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