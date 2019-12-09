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

import binascii
import re

from .config import cfg
from .constants import ARCHITECTURE_TYPE
from .globals import (DUMMY_IAID,
                      DUMMY_MAC,
                      EMPTY_OPTIONS,
                      IGNORED_LOG_OPTIONS,
                      timer)
from .helpers import (colonify_ip6,
                      combine_prefix_length,
                      convert_binary_to_dns,
                      split_prefix)


class Transaction:
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
        self.MAC = DUMMY_MAC
        # last message for following the protocol
        self.LastMessageReceivedType = message_type
        # dictionary for options
        self.OptionsRaw = options
        # default dummy OptionsRequest
        self.OptionsRequest = list()
        # timestamp to manage/clean transactions
        self.Timestamp = timer
        # dummy hostname
        self.FQDN = ''
        self.Hostname = ''
        # DNS Options for option 39
        self.DNS_N = 0
        self.DNS_O = 0
        self.DNS_S = 0
        # dummy IAID
        self.IAID = DUMMY_IAID
        # dummy IAT1
        self.IAT1 = cfg.T1
        # dummy IAT2
        self.IAT2 = cfg.T2
        # IA option - NA, TA or PD -> DHCPv6 option 3, 4 or 25
        # to be used in option_requests in Handler.build_response()
        self.IA_Options = list()
        # Addresses given by client, for example for RENEW or RELEASE requests
        self.Addresses = list()
        # same with prefixes
        self.Prefixes = list()
        # might be used against clients that are running wild
        # initial 1 as being increased after handling
        self.Counter = 1
        # temporary storage for client configuration from DB config
        # - only used if config comes from DB
        self.ClientConfigDB = None
        # client config from config store
        self.Client = None
        # Vendor Class Option
        self.VendorClassEN = None
        self.VendorClassData = ''
        # Rapid Commit flag
        self.RapidCommit = False
        # answer type - take from class definition, one of 'normal', 'noaddress', 'noprefix' or 'none'
        # defaults to 'normal' as this is the main purpose of dhcpy6d
        self.Answer = 'normal'
        # default DUID values
        self.DUID = ''
        # self.DUIDType = 1
        # self.DUID_EN = 0
        # Elapsed Time - option 8, at least sent by WIDE dhcp6c when requesting delegated prefix
        self.ElapsedTime = 0
        # Client architecture type (RFC 5970)
        self.ClientArchitecture = ''
        # Known client architecture type (RFC 4578) (e.g. EFI x86 - 64)
        self.KnownClientArchitecture = ''
        # UserClass (https://tools.ietf.org/html/rfc3315#section-22.15)
        self.UserClass = ''

        # DUID of client
        # 1 Client Identifier Option
        if 1 in options:
            self.DUID = options[1]
            # self.DUIDType = int(options[1][0:4], 16)
            # # DUID-EN can be retrieved from DUID
            # if self.DUIDType == 2:
            #     # some HP printers seem to produce pretty bad requests, thus some cleaning is necessary
            #     # e.g. '1 1 1 00020000000b0026b1f72a49' instead of '00020000000b0026b1f72a49'
            #     self.DUID_EN = int(options[1].split(' ')[-1][4:12], 16)

        # Identity Association for Non-temporary Addresses
        # 3 Identity Association for Non-temporary Address Option
        if 3 in options:
            for payload in options[3]:
                self.IAID = payload[0:8]
                self.IAT1 = int(payload[8:16], 16)
                self.IAT2 = int(payload[16:24], 16)

                # addresses given by client if any
                for a in range(len(payload[32:])//44):
                    address = payload[32:][(a*56):(a*56)+32]
                    # in case an address is asked for twice by one host ignore the twin
                    if not address in self.Addresses:
                        self.Addresses.append(address)
            self.IA_Options.append(3)

        # Identity Association for Temporary Addresses
        # 4 Identity Association for Temporary Address Option
        if 4 in options:
            for payload in options[4]:
                self.IAID = payload[0:8]
                self.IAT1 = int(payload[8:16], 16)
                self.IAT2 = int(payload[16:24], 16)

                # addresses given by client if any
                for a in range(len(payload[32:])//44):
                    address = payload[32:][(a*56):(a*56)+32]
                    # in case an address is asked for twice by one host ignore the twin
                    if not address in self.Addresses:
                        self.Addresses.append(address)
            self.IA_Options.append(4)

        # Options Requested
        # 6 Option Request Option
        if 6 in options:
            options_request = list()
            opts = options[6][:]
            while len(opts) > 0:
                options_request.append(int(opts[0:4], 16))
                opts = opts[4:]
            self.OptionsRequest = options_request

        # 8 Elapsed Time
        # RFC 3315: This time is expressed in hundredths of a second (10^-2 seconds).
        if 8 in options:
            self.ElapsedTime = int(options[8][0:8], 16)

        # 14 Rapid Commit flag
        if 14 in options:
            self.RapidCommit = True

        # 15 User Class Option
        if 15 in options:
            user_class_raw = options[15]
            # raw user class is prefixed with null byte (00 in hex) and eot (04 in hex)
            self.UserClass = binascii.a2b_hex(user_class_raw[4:])

        # 16 Vendor Class Option
        if 16 in options:
            self.VendorClassEN = int(options[16][0:8], 16)
            self.VendorClassData = binascii.unhexlify(options[16][12:])

        # Identity Association for Prefix Delegation
        # 25 Identity Association for Prefix Delegation
        if 25 in options:
            for payload in options[25]:
                self.IAID = payload[0:8]
                self.IAT1 = int(payload[8:16], 16)
                self.IAT2 = int(payload[16:24], 16)

                # iaid        t1        t2       ia_prefix   opt_length       preferred validlt    length    prefix
                #00000001    ffffffff  ffffffff  001a        0019             00000e10   00001518    30     fd661234000000000000000000000000
                #8               16      24      28          32                  40      48          50      82

                # Prefixes given by client if any
                for p in range(len(payload[32:])//50):
                    prefix = payload[50:][(p*58):(p*58)+32]
                    length = int(payload[48:][(p*58):(p*58)+2], 16)
                    prefix_combined = combine_prefix_length(prefix, length)
                    # in case a prefix is asked for twice by one host ignore the twin
                    if not prefix_combined in self.Prefixes:
                        self.Prefixes.append(prefix_combined)
                    del(prefix, length, prefix_combined)
            self.IA_Options.append(25)

        # FQDN
        # 39 FQDN Option
        if 39 in options:
            bits = ('%4s' % (str(bin(int(options[39][1:2]))).strip('0b'))).replace(' ', '0')
            self.DNS_N = int(bits[1])
            self.DNS_O = int(bits[2])
            self.DNS_S = int(bits[3])
            # only hostname needed
            self.FQDN = convert_binary_to_dns(options[39][2:])
            self.Hostname = self.FQDN.split('.')[0].lower()
            # test if hostname is valid
            n = re.compile('^([a-z0-9\-\_]+)*$')
            if n.match(self.Hostname) == None:
                self.Hostname = ''
            del n

        # Client architecture type
        # 61 Client System Architecture Type Option
        if 61 in options:
            # raw client architecture is supplied as a 16-bit integer (e. g. 0007)
            # See https://tools.ietf.org/html/rfc4578#section-2.1
            client_architecture_raw = options[61]
            # short number (0007 => 7 for dictionary usage)
            client_architecture_short = int(client_architecture_raw)

            self.ClientArchitecture = client_architecture_raw

            if client_architecture_short in ARCHITECTURE_TYPE:
                self.KnownClientArchitecture = ARCHITECTURE_TYPE[client_architecture_short]

    def _get_options_string(self):
        """
            get all options in one string for debugging
        """
        optionsstring = ''
        # put own attributes into a string
        options = sorted(list(self.__dict__.keys()))
        # options.sort()
        for o in options:
            # ignore some attributes
            if not o in IGNORED_LOG_OPTIONS and \
               not self.__dict__[o] in EMPTY_OPTIONS:
                if o == 'Addresses':
                    if (3 or 4) in self.IA_Options:
                        option = 'Addresses:'
                        for a in self.__dict__[o]:
                            option += ' ' + colonify_ip6(a)
                        optionsstring = optionsstring + ' | '  + option
                elif o == 'Prefixes':
                    if 25 in self.IA_Options:
                        option = 'Prefixes:'
                        for p in self.__dict__[o]:
                            prefix, length = split_prefix(p)
                            option += combine_prefix_length(colonify_ip6(prefix), length)
                elif o == 'ClientLLIP':
                    option = 'ClientLLIP: ' + colonify_ip6(self.__dict__['ClientLLIP'])
                    optionsstring = optionsstring + ' | '  + option
                else:
                    option = o + ': ' + str(self.__dict__[o])
                    optionsstring = optionsstring + ' | '  + option

        return optionsstring