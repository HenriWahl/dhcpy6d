# encoding: utf8
#
# DHCPy6d DHCPv6 Daemon
#
# Copyright (C) 2009-2015 Henri Wahl <h.wahl@ifw-dresden.de>
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

# DHCPv6
MESSAGE_TYPES = { 1:"SOLICIT", 2:"ADVERTISE", 3:"REQUEST", 4:"CONFIRM", 5:"RENEW", \
                6:"REBIND", 7:"REPLY", 8:"RELEASE", 9:"DECLINE", 10:"RECONFIGURE", \
                11:"INFORMATION-REQUEST", 12:"RELAY-FORW", 13:"RELAY-REPL" }

# DUID               
DUID_TYPES = { 1:"DUID-LLT", 2:"DUID-EN", 3:"DUID-LL" }

# see http://www.iana.org/assignments/dhcpv6-parameters/
OPTION_REQUEST = {   1:"OPTION_CLIENTID",\
                     2:"OPTION_SERVERID",\
                     3:"OPTION_IA_NA",\
                     4:"OPTION_IA_TA",\
                     5:"OPTION_IAADDR",\
                     6:"OPTION_ORO",\
                     7:"OPTION_PREFERENCE",\
                     8:"OPTION_ELAPSED_TIME",\
                     9:"OPTION_RELAY_MSG",\
                    10:"Unassigned",\
                    11:"OPTION_AUTH",\
                    12:"OPTION_UNICAST", \
                    13:"OPTION_STATUS_CODE", \
                    14:"OPTION_RAPID_COMMIT",\
                    15:"OPTION_USER_CLASS",\
                    16:"OPTION_VENDOR_CLASS",\
                    17:"OPTION_VENDOR_OPTS",\
                    18:"OPTION_INTERFACE_ID",\
                    19:"OPTION_RECONF_MSG",\
                    20:"OPTION_RECONF_ACCEPT",\
                    21:"SIP Servers Domain Name List",\
                    22:"SIP Servers IPv6 Address List",\
                    23:"DNS Recursive Name Server Option",\
                    24:"Domain Search List option",\
                    25:"OPTION_IA_PD",\
                    26:"OPTION_IAPREFIX",\
                    27:"OPTION_NIS_SERVERS",\
                    28:"OPTION_NISP_SERVERS",\
                    29:"OPTION_NIS_DOMAIN_NAME",\
                    30:"OPTION_NISP_DOMAIN_NAME",\
                    31:"OPTION_SNTP_SERVERS",\
                    32:"OPTION_INFORMATION_REFRESH_TIME",\
                    33:"OPTION_BCMCS_SERVER_D",\
                    34:"OPTION_BCMCS_SERVER_A",\
                    35:"Unassigned",\
                    36:"OPTION_GEOCONF_CIVIC",\
                    37:"OPTION_REMOTE_ID",\
                    38:"OPTION_SUBSCRIBER_ID",\
                    39:"OPTION_CLIENT_FQDN",\
                    40:"OPTION_PANA_AGENT",\
                    41:"OPTION_NEW_POSIX_TIMEZONE",\
                    42:"OPTION_NEW_TZDB_TIMEZONE",\
                    43:"OPTION_ERO",\
                    44:"OPTION_LQ_QUERY",\
                    45:"OPTION_CLIENT_DATA",\
                    46:"OPTION_CLT_TIME",\
                    47:"OPTION_LQ_RELAY_DATA",\
                    48:"OPTION_LQ_CLIENT_LINK",\
                    49:"OPTION_MIP6_HNINF",\
                    50:"OPTION_MIP6_RELAY",\
                    51:"OPTION_V6_LOST",\
                    52:"OPTION_CAPWAP_AC_V6",\
                    53:"OPTION_RELAY_ID",\
                    54:"OPTION-IPv6_Address-MoS",\
                    55:"OPTION-IPv6_FQDN-MoS"\
                    }
                   
STATUS_CODE = { 0:"Success",\
                1:"Failure",\
                2:"No Addresses available",\
                3:"No Binding",\
                4:"Prefix not appropriate for link",\
                5:"Use Multicast"
                }