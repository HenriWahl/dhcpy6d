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

import re
import sys
import traceback

from ..config import (Address,
                      cfg,
                      Prefix)
from ..dns import get_ip_from_dns
from ..globals import (DUMMY_MAC,
                       EMPTY_OPTIONS,
                       IGNORED_LOG_OPTIONS,
                       timer,
                       transactions)
from ..helpers import (colonify_ip6,
                       decompress_ip6,
                       decompress_prefix,
                       split_prefix)
from ..log import log
from ..storage import (config_store,
                       volatile_store)

from .parse_pattern import (parse_pattern_address,
                            parse_pattern_prefix)


class Client:
    """
        client object, generated from configuration database or on the fly
    """
    def __init__(self, transaction_id=None):
        # Addresses, depending on class or fixed addresses
        self.addresses = list()
        # Bootfiles, depending on class and architecture
        self.bootfiles = list()
        # Last chosen Bootfile
        self.chosen_boot_file = ''
        # Prefixes, depending on class or fixed prefixes
        self.prefixes = list()
        # DUID
        self.duid = ''
        # Hostname
        self.hostname = ''
        # Class/role of client - sadly "class" is a keyword and "class_" is more error prone
        self.client_class = ''
        # MAC
        self.mac = ''
        # timestamp of last update
        self.last_update = ''

        # when an transaction_id is given build the client
        if not transaction_id is None:
            self.build(transaction_id)

    def get_options_string(self):
        """
            all attributes in a string for logging
        """
        options_string = ''
        # put own attributes into a string
        options = sorted(list(self.__dict__.keys()))
        # options.sort()
        for o in options:
            # ignore some attributes
            if not o in IGNORED_LOG_OPTIONS and \
               not self.__dict__[o] in EMPTY_OPTIONS:
                if o == 'addresses':
                    if 'addresses' in cfg.CLASSES[self.client_class].ADVERTISE:
                        option = o + ':'
                        for a in self.__dict__[o]:
                            option += ' ' + colonify_ip6(a.ADDRESS)
                        options_string = options_string + ' | '  + option
                elif o == 'bootfiles':
                    option = o + ':'
                    for a in self.__dict__[o]:
                        option += ' ' + a.BOOTFILE_URL
                    options_string = options_string + ' | '  + option
                elif o == 'prefixes':
                    if 'prefixes' in cfg.CLASSES[self.client_class].ADVERTISE:
                        option = o + ':'
                        for p in self.__dict__[o]:
                            option += ' {0}/{1}'.format(colonify_ip6(p.PREFIX), p.LENGTH)
                        options_string = options_string + ' | '  + option
                elif o == 'mac':
                    if self.__dict__[o] != DUMMY_MAC:
                        option = o + ': ' + str(self.__dict__[o])
                        options_string = options_string + ' | ' + option
                else:
                    option = o + ': ' + str(self.__dict__[o])
                    options_string = options_string + ' | '  + option
        return options_string

    def build(self, transaction_id):
        """
            builds client object of client config and transaction data
            checks if filters apply
            check if lease is still valid for RENEW and REBIND answers
            check if invalid addresses need to get deleted with lifetime 0
        """
        try:
            # create client object
            #client = Client()

            # configuration from client deriving from general config or filters - defaults to none
            client_config = None

            # list to collect filtered client information
            # if there are more than one entries that do not match the class is not uniquely identified
            filtered_class = {}

            # check if there are identification attributes of any class - classes are sorted by filter types
            for f in cfg.FILTERS:
                # look into all classes and their filters
                for c in cfg.FILTERS[f]:
                    # check further only if class applies to interface
                    if transactions[transaction_id].interface in c.INTERFACE:
                        # MACs
                        if c.FILTER_MAC != '':
                            pattern = re.compile(c.FILTER_MAC)
                            # if mac filter fits client mac address add client config
                            if len(pattern.findall(transactions[transaction_id].mac)) > 0:
                                client_config = config_store.get_client_config(hostname=transactions[transaction_id].hostname,
                                                                               mac=[transactions[transaction_id].mac],
                                                                               duid=transactions[transaction_id].duid,
                                                                               aclass=c.NAME)
                                # add classname to dictionary - if there are more than one entry classes do not match
                                # and thus are invalid
                                filtered_class[c.NAME] = c
                        # DUIDs
                        if c.FILTER_DUID != '':
                            pattern = re.compile(c.FILTER_DUID)
                            # if duid filter fits client duid address add client config
                            if len(pattern.findall(transactions[transaction_id].duid)) > 0:
                                client_config = config_store.get_client_config(hostname=transactions[transaction_id].hostname,
                                                                               mac=[transactions[transaction_id].mac],
                                                                               duid=transactions[transaction_id].duid,
                                                                               aclass=c.NAME)
                                # see above
                                filtered_class[c.NAME] = c
                        # HOSTNAMEs
                        if c.FILTER_HOSTNAME != '':
                            pattern = re.compile(c.FILTER_HOSTNAME)
                            # if hostname filter fits client hostname address add client config
                            if len(pattern.findall(transactions[transaction_id].hostname)) > 0:
                                client_config = config_store.get_client_config(hostname=transactions[transaction_id].hostname,
                                                                               mac=[transactions[transaction_id].mac],
                                                                               duid=transactions[transaction_id].duid,
                                                                               aclass=c.NAME)
                                # see above
                                filtered_class[c.NAME] = c

            # if there are more than 1 different classes matching for the client they are not valid
            if len(filtered_class) != 1:
                client_config = None

            # if filters did not get a result try it the hard way
            if client_config is None:
                # check all given identification criteria - if they all match each other the client is identified
                id_attributes = list()

                # get client config that most probably seems to fit
                config_store.build_config_from_db(transaction_id)

                # check every attribute which is required
                # depending on identificaton mode empty results are ignored or considered
                # finally all attributes are grouped in sets and for a correctly identified host
                # only one entry should appear at the end
                for identification in cfg.IDENTIFICATION:
                    if identification == 'mac':
                        # get all MACs for client from config
                        macs = config_store.get_client_config_by_mac(transaction_id)
                        if macs:
                            macs = set(macs)
                            id_attributes.append('macs')
                        elif cfg.IDENTIFICATION_MODE == 'match_all':
                            macs = set()
                            id_attributes.append('macs')

                    if identification == 'duid':
                        duids = config_store.get_client_config_by_duid(transaction_id)
                        if duids:
                            duids = set(duids)
                            id_attributes.append('duids')
                        elif cfg.IDENTIFICATION_MODE == 'match_all':
                            duids = set()
                            id_attributes.append('duids')

                    if identification == 'hostname':
                        hostnames = config_store.get_client_config_by_hostname(transaction_id)
                        if hostnames:
                            hostnames = set(hostnames)
                            id_attributes.append('hostnames')
                        elif cfg.IDENTIFICATION_MODE == 'match_all':
                            hostnames = set()
                            id_attributes.append('hostnames')

                # get intersection of all sets of identifying attributes - even the empty ones
                if len(id_attributes) > 0:
                    client_config = set.intersection(eval('&'.join(id_attributes)))

                    # if exactly one client has been identified use that config
                    if len(client_config) == 1:
                        # reuse client_config, grab it out of the set
                        client_config = client_config.pop()
                    else:
                        # in case there is no client config we should maybe log this?
                        client_config = None
                else:
                    client_config = None

            # If client gave some addresses for RENEW or REBIND consider them
            if transactions[transaction_id].last_message_received_type in (5, 6) and\
                not (len(transactions[transaction_id].addresses) == 0 and \
                     len(transactions[transaction_id].prefixes) == 0):
                if not client_config is None:
                    # give client hostname
                    self.hostname = client_config.HOSTNAME
                    self.client_class = client_config.CLASS
                    # apply answer type of client to transaction - useful if no answer or no address available is configured
                    transactions[transaction_id].Answer = cfg.CLASSES[self.client_class].ANSWER
                else:
                    # use default class if host is unknown
                    self.hostname = transactions[transaction_id].hostname
                    self.client_class = 'default_' + transactions[transaction_id].interface
                    # apply answer type of client to transaction - useful if no answer or no address available is configured
                    transactions[transaction_id].Answer = cfg.CLASSES[self.client_class].ANSWER

                if 'addresses' in cfg.CLASSES[self.client_class].ADVERTISE and \
                    (3 or 4) in transactions[transaction_id].ia_options:
                    for address in transactions[transaction_id].addresses:
                        # check_lease returns hostname, address, type, category, ia_type, class, preferred_until of leased address
                        answer = volatile_store.check_lease(address, transaction_id)
                        if answer:
                            if len(answer) > 0:
                                for item in answer:
                                    a = dict(list(zip(('hostname', 'address', 'type', 'category', 'ia_type', 'class', 'preferred_until'), item)))
                                    # if lease exists but no configured client set class to default
                                    if client_config is None:
                                        self.hostname = transactions[transaction_id].hostname
                                        self.client_class = 'default_' + transactions[transaction_id].interface
                                    # check if address type of lease still exists in configuration
                                    # and if request interface matches that of class
                                    if a['class'] in cfg.CLASSES and self.client_class == a['class'] and\
                                       transactions[transaction_id].interface in cfg.CLASSES[self.client_class].INTERFACE:
                                        # type of address must be defined in addresses for this class
                                        # or fixed/dns - in which case it is not class related
                                        if a['type'] in cfg.CLASSES[a['class']].ADDRESSES or a['type'] in ['fixed']:
                                            # flag for lease usage
                                            use_lease = True
                                            # test lease validity against address prototype pattern only if not fixed or from DNS
                                            if not a['category'] in ['fixed', 'dns']:
                                                # test if address matches pattern
                                                for identification in range(len(address)):
                                                    if address[identification] != cfg.ADDRESSES[a['type']].PROTOTYPE[identification] and \
                                                       cfg.ADDRESSES[a['type']].PROTOTYPE[identification] != 'x':
                                                        use_lease = False
                                                        break
                                            elif a['category'] == 'fixed' and not client_config.ADDRESS is None:
                                                if not address in client_config.ADDRESS:
                                                    use_lease = False
                                            elif a['category'] == 'dns':
                                                use_lease = False

                                            # only use lease if it still matches prototype
                                            if use_lease:
                                                # when category is range, test if it still applies
                                                if a['category'] == 'range':
                                                    # borrowed from parse_pattern_address to find out if lease is still in a meanwhile maybe changed range
                                                    range_from, range_to = cfg.ADDRESSES[a['type']].RANGE.split('-')

                                                    # correct possible misconfiguration
                                                    if len(range_from)<4:
                                                        range_from ='0'*(4-len(range_from)) + range_from
                                                    if len(range_to)<4:
                                                        range_to ='0'*(4-len(range_to)) + range_to
                                                    if range_from > range_to:
                                                        range_from, range_to = range_to, range_from
                                                    # if lease is still inside range boundaries use it
                                                    if range_from <= address[28:].lower() < range_to:
                                                        # build IA partly of leases db, partly of config db
                                                        ia = Address(address=a['address'],
                                                                     atype=a['type'],
                                                                     preferred_lifetime=cfg.ADDRESSES[a['type']].PREFERRED_LIFETIME,
                                                                     valid_lifetime=cfg.ADDRESSES[a['type']].VALID_LIFETIME,
                                                                     category=a['category'],
                                                                     ia_type=a['ia_type'],
                                                                     aclass=a['class'],
                                                                     dns_update=cfg.ADDRESSES[a['type']].DNS_UPDATE,
                                                                     dns_zone=cfg.ADDRESSES[a['type']].DNS_ZONE,
                                                                     dns_rev_zone=cfg.ADDRESSES[a['type']].DNS_REV_ZONE,
                                                                     dns_ttl=cfg.ADDRESSES[a['type']].DNS_TTL)
                                                        self.addresses.append(ia)

                                                # de-preferred random address has to be deleted and replaced
                                                elif a['category'] == 'random' and timer > a['preferred_until']:
                                                    # create new random address if old one is depreferred
                                                    random_address = parse_pattern_address(cfg.ADDRESSES[a['type']], client_config, transaction_id)
                                                    # create new random address if old one is de-preferred
                                                    # do not wait until it is invalid
                                                    if not random_address is None:
                                                        ia = Address(address=random_address, ia_type=cfg.ADDRESSES[a['type']].IA_TYPE,
                                                                     preferred_lifetime=cfg.ADDRESSES[a['type']].PREFERRED_LIFETIME,
                                                                     valid_lifetime=cfg.ADDRESSES[a['type']].VALID_LIFETIME,
                                                                     category='random',
                                                                     aclass=cfg.ADDRESSES[a['type']].CLASS,
                                                                     atype=cfg.ADDRESSES[a['type']].TYPE,
                                                                     dns_update=cfg.ADDRESSES[a['type']].DNS_UPDATE,
                                                                     dns_zone=cfg.ADDRESSES[a['type']].DNS_ZONE,
                                                                     dns_rev_zone=cfg.ADDRESSES[a['type']].DNS_REV_ZONE,
                                                                     dns_ttl=cfg.ADDRESSES[a['type']].DNS_TTL)
                                                        self.addresses.append(ia)
                                                        # set de-preferred address invalid
                                                        self.addresses.append(Address(address=a['address'], valid=False,
                                                                                      preferred_lifetime=0,
                                                                                      valid_lifetime=0))

                                                else:
                                                    # build IA partly of leases db, partly of config db
                                                    ia = Address(address=a['address'],
                                                                 atype=a['type'],
                                                                 preferred_lifetime=cfg.ADDRESSES[a['type']].PREFERRED_LIFETIME,
                                                                 valid_lifetime=cfg.ADDRESSES[a['type']].VALID_LIFETIME,
                                                                 category=a['category'],
                                                                 ia_type=a['ia_type'],
                                                                 aclass=a['class'],
                                                                 dns_update=cfg.ADDRESSES[a['type']].DNS_UPDATE,
                                                                 dns_zone=cfg.ADDRESSES[a['type']].DNS_ZONE,
                                                                 dns_rev_zone=cfg.ADDRESSES[a['type']].DNS_REV_ZONE,
                                                                 dns_ttl=cfg.ADDRESSES[a['type']].DNS_TTL)
                                                    self.addresses.append(ia)

                    # important indent here, has to match for...addresses-loop!
                    # look for addresses in transaction that are invalid and add them
                    # to client addresses with flag invalid and a RFC-compliant lifetime of 0
                    for a in set(transactions[transaction_id].addresses).difference([decompress_ip6(x.ADDRESS) for x in self.addresses]):
                        self.addresses.append(Address(address=a,
                                                      valid=False,
                                                      preferred_lifetime=0,
                                                      valid_lifetime=0))

                if 'prefixes' in cfg.CLASSES[self.client_class].ADVERTISE and \
                   25 in transactions[transaction_id].ia_options:
                    for prefix in transactions[transaction_id].prefixes:
                        # split prefix of prefix from length, separated by /
                        prefix_prefix, prefix_length = split_prefix(prefix)

                        # check_prefix returns hostname, prefix, length, type, category, class, preferred_until of leased address
                        answer = volatile_store.check_prefix(prefix_prefix, prefix_length, transaction_id)

                        if answer:
                            if len(answer) > 0:
                                for item in answer:
                                    p = dict(list(zip(('hostname', 'prefix', 'length', 'type', 'category', 'class', 'preferred_until'), item)))
                                    # if lease exists but no configured client set class to default
                                    if client_config is None:
                                        self.hostname = transactions[transaction_id].hostname
                                        self.client_class = 'default_' + transactions[transaction_id].interface
                                    # check if address type of lease still exists in configuration
                                    # and if request interface matches that of class
                                    if p['class'] in cfg.CLASSES and self.client_class == p['class'] and\
                                       transactions[transaction_id].interface in cfg.CLASSES[self.client_class].INTERFACE:
                                        # type of address must be defined in addresses for this class
                                        # or fixed/dns - in which case it is not class related
                                        if p['type'] in cfg.CLASSES[p['class']].PREFIXES:
                                            # flag for lease usage
                                            use_lease = True
                                            # test if prefix matches pattern
                                            for identification in range(len(prefix_prefix)):
                                                if prefix_prefix[identification] != cfg.PREFIXES[p['type']].PROTOTYPE[identification] and \
                                                   cfg.PREFIXES[p['type']].PROTOTYPE[identification] != 'x':
                                                    use_lease = False
                                                    break
                                            # only use prefix if it still matches prototype
                                            if use_lease:
                                                # when category is range, test if it still applies
                                                if p['category'] == 'range':
                                                    # borrowed from parse_pattern_prefix to find out if lease is still in a meanwhile maybe changed range
                                                    range_from, range_to = cfg.PREFIXES[p['type']].RANGE.split('-')

                                                    # correct possible misconfiguration
                                                    if len(range_from)<4:
                                                        range_from ='0'*(4-len(range_from)) + range_from
                                                    if len(range_to)<4:
                                                        range_to ='0'*(4-len(range_to)) + range_to
                                                    if range_from > range_to:
                                                        range_from, range_to = range_to, range_from

                                                    # contrary to addresses the prefix $range$ part of the pattern is expected somewhere at the left part of the pattern
                                                    # here the 128 Bit sum up to 32 characters in address/prefix string so prefix_range_index has to be calculated
                                                    # as first character of range part of prefix - assuming steps of width 4
                                                    prefix_range_index = int(cfg.PREFIXES[p['type']].LENGTH) // 4 - 4
                                                    # prefix itself has a prefix - the first part of the prefix pattern
                                                    prefix_prefix = decompress_ip6(p['prefix'].replace('$range$', '0000'))[:prefix_range_index + 4]

                                                    # if lease is still inside range boundaries use it
                                                    if range_from <= prefix_prefix[prefix_range_index:prefix_range_index + 4].lower() < range_to:
                                                        # build IA partly of leases db, partly of config db
                                                        ia = Prefix(prefix=p['prefix'],
                                                                    length=p['length'],
                                                                    ptype=p['type'],
                                                                    preferred_lifetime=cfg.PREFIXES[p['type']].PREFERRED_LIFETIME,
                                                                    valid_lifetime=cfg.PREFIXES[p['type']].VALID_LIFETIME,
                                                                    category=p['category'],
                                                                    pclass=p['class'],
                                                                    route_link_local=cfg.PREFIXES[p['type']].ROUTE_LINK_LOCAL)
                                                        self.prefixes.append(ia)

                    # important indent here, has to match for...prefixes-loop!
                    # look for prefixes in transaction that are invalid and add them
                    # to client prefixes with flag invalid and a RFC-compliant lifetime of 0
                    if len(self.prefixes) > 0:
                        for p in set(transactions[transaction_id].prefixes).difference([decompress_prefix(x.PREFIX, x.LENGTH) for x in self.prefixes]):
                            prefix, length = split_prefix(p)
                            self.prefixes.append(Prefix(prefix=prefix,
                                                        length=length,
                                                        valid=False,
                                                        preferred_lifetime=0,
                                                        valid_lifetime=0))
                            del(prefix, length)

                # return client

            # build IA addresses from config - fixed ones and dynamic
            if client_config != None:
                # give client hostname + class
                self.hostname = client_config.HOSTNAME
                self.client_class = client_config.CLASS
                # apply answer type of client to transaction - useful if no answer or no address available is configured
                transactions[transaction_id].Answer = cfg.CLASSES[self.client_class].ANSWER
                # continue only if request interface matches class interfaces
                if transactions[transaction_id].interface in cfg.CLASSES[self.client_class].INTERFACE:
                    # if fixed addresses are given build them
                    if not client_config.ADDRESS is None:
                        for address in client_config.ADDRESS:
                            if len(address) > 0:
                                # fixed addresses are assumed to be non-temporary
                                #
                                # todo: lifetime of address should be set by config too
                                #
                                ia = Address(address=address,
                                             ia_type='na',
                                             preferred_lifetime=cfg.PREFERRED_LIFETIME,
                                             valid_lifetime=cfg.VALID_LIFETIME,
                                             category='fixed',
                                             aclass='fixed',
                                             atype='fixed')

                                self.addresses.append(ia)

                    if not client_config.CLASS == '':
                        # add all addresses which belong to that class
                        for address in cfg.CLASSES[client_config.CLASS].ADDRESSES:
                            # addresses of category 'dns' will be searched in DNS
                            if cfg.ADDRESSES[address].CATEGORY == 'dns':
                                a = get_ip_from_dns(self.hostname)
                            else:
                                a = parse_pattern_address(cfg.ADDRESSES[address], client_config, transaction_id)
                            # in case range has been exceeded a will be None
                            if a:
                                ia = Address(address=a,
                                             ia_type=cfg.ADDRESSES[address].IA_TYPE,
                                             preferred_lifetime=cfg.ADDRESSES[address].PREFERRED_LIFETIME,
                                             valid_lifetime=cfg.ADDRESSES[address].VALID_LIFETIME,
                                             category=cfg.ADDRESSES[address].CATEGORY,
                                             aclass=cfg.ADDRESSES[address].CLASS,
                                             atype=cfg.ADDRESSES[address].TYPE,
                                             dns_update=cfg.ADDRESSES[address].DNS_UPDATE,
                                             dns_zone=cfg.ADDRESSES[address].DNS_ZONE,
                                             dns_rev_zone=cfg.ADDRESSES[address].DNS_REV_ZONE,
                                             dns_ttl=cfg.ADDRESSES[address].DNS_TTL)
                                self.addresses.append(ia)

                        # add all bootfiles which belong to that class
                        for bootfile in cfg.CLASSES[client_config.CLASS].BOOTFILES:
                            client_architecture = cfg.BOOTFILES[bootfile].CLIENT_ARCHITECTURE
                            user_class = cfg.BOOTFILES[bootfile].USER_CLASS

                            # check if transaction attributes matches the bootfile defintion
                            if (not client_architecture or \
                                transactions[transaction_id].client_architecture == client_architecture or \
                                transactions[transaction_id].known_client_architecture == client_architecture) and \
                               (not user_class or \
                                transactions[transaction_id].UserClass == user_class):
                                self.bootfiles.append(cfg.BOOTFILES[bootfile])


                        if 'prefixes' in cfg.CLASSES[client_config.CLASS].ADVERTISE and \
                           25 in transactions[transaction_id].ia_options:
                            for prefix in cfg.CLASSES[client_config.CLASS].PREFIXES:
                                p = parse_pattern_prefix(cfg.PREFIXES[prefix], client_config, transaction_id)
                                # in case range has been exceeded p will be None
                                if p:
                                    ia_pd = Prefix(prefix=p,
                                                   length=cfg.PREFIXES[prefix].LENGTH,
                                                   preferred_lifetime=cfg.PREFIXES[prefix].PREFERRED_LIFETIME,
                                                   valid_lifetime=cfg.PREFIXES[prefix].VALID_LIFETIME,
                                                   category=cfg.PREFIXES[prefix].CATEGORY,
                                                   pclass=cfg.PREFIXES[prefix].CLASS,
                                                   ptype=cfg.PREFIXES[prefix].TYPE,
                                                   route_link_local=cfg.PREFIXES[prefix].ROUTE_LINK_LOCAL)
                                    self.prefixes.append(ia_pd)

                    if client_config.ADDRESS == client_config.CLASS == '':
                        # use default class if no class or address is given
                        for address in cfg.CLASSES['default_' + transactions[transaction_id].interface].ADDRESSES:
                            self.client_class = 'default_' + transactions[transaction_id].interface
                            # addresses of category 'dns' will be searched in DNS
                            if cfg.ADDRESSES[address].CATEGORY == 'dns':
                                a = get_ip_from_dns(self.hostname)
                            else:
                                a = parse_pattern_address(cfg.ADDRESSES[address], client_config, transaction_id)
                            if a:
                                ia = Address(address=a, ia_type=cfg.ADDRESSES[address].IA_TYPE,
                                             preferred_lifetime=cfg.ADDRESSES[address].PREFERRED_LIFETIME,
                                             valid_lifetime=cfg.ADDRESSES[address].VALID_LIFETIME,
                                             category=cfg.ADDRESSES[address].CATEGORY,
                                             aclass=cfg.ADDRESSES[address].CLASS,
                                             atype=cfg.ADDRESSES[address].TYPE,
                                             dns_update=cfg.ADDRESSES[address].DNS_UPDATE,
                                             dns_zone=cfg.ADDRESSES[address].DNS_ZONE,
                                             dns_rev_zone=cfg.ADDRESSES[address].DNS_REV_ZONE,
                                             dns_ttl=cfg.ADDRESSES[address].DNS_TTL)
                                self.addresses.append(ia)

                        for bootfile in cfg.CLASSES['default_' + transactions[transaction_id].interface].BOOTFILES:
                            client_architecture = bootfile.CLIENT_ARCHITECTURE
                            user_class = bootfile.USER_CLASS

                            # check if transaction attributes matches the bootfile defintion
                            if (not client_architecture or \
                                transactions[transaction_id].client_architecture == client_architecture or \
                                transactions[transaction_id].known_client_architecture == client_architecture) and \
                               (not user_class or \
                                transactions[transaction_id].UserClass == user_class):
                                self.bootfiles.append(bootfile)
            else:
                # use default class if host is unknown
                self.hostname = transactions[transaction_id].hostname
                self.client_class = 'default_' + transactions[transaction_id].interface
                # apply answer type of client to transaction - useful if no answer or no address available is configured
                transactions[transaction_id].Answer = cfg.CLASSES[self.client_class].ANSWER

                if 'addresses' in cfg.CLASSES['default_' + transactions[transaction_id].interface].ADVERTISE and \
                    (3 or 4) in transactions[transaction_id].ia_options:
                    for address in cfg.CLASSES['default_' + transactions[transaction_id].interface].ADDRESSES:
                        # addresses of category 'dns' will be searched in DNS
                        if cfg.ADDRESSES[address].CATEGORY == 'dns':
                            a = get_ip_from_dns(self.hostname)
                        else:
                            a = parse_pattern_address(cfg.ADDRESSES[address], self, transaction_id)
                        if a:
                            ia = Address(address=a, ia_type=cfg.ADDRESSES[address].IA_TYPE,
                                         preferred_lifetime=cfg.ADDRESSES[address].PREFERRED_LIFETIME,
                                         valid_lifetime=cfg.ADDRESSES[address].VALID_LIFETIME,
                                         category=cfg.ADDRESSES[address].CATEGORY,
                                         aclass=cfg.ADDRESSES[address].CLASS,
                                         atype=cfg.ADDRESSES[address].TYPE,
                                         dns_update=cfg.ADDRESSES[address].DNS_UPDATE,
                                         dns_zone=cfg.ADDRESSES[address].DNS_ZONE,
                                         dns_rev_zone=cfg.ADDRESSES[address].DNS_REV_ZONE,
                                         dns_ttl=cfg.ADDRESSES[address].DNS_TTL)
                            self.addresses.append(ia)

                if 'prefixes' in cfg.CLASSES['default_' + transactions[transaction_id].interface].ADVERTISE and \
                    25 in transactions[transaction_id].ia_options:

                    for prefix in cfg.CLASSES['default_' + transactions[transaction_id].interface].PREFIXES:
                        p = parse_pattern_prefix(cfg.PREFIXES[prefix], client_config, transaction_id)
                        # in case range has been exceeded p will be None
                        if p:
                            ia_pd = Prefix(prefix=p,
                                           length=cfg.PREFIXES[prefix].LENGTH,
                                           preferred_lifetime=cfg.PREFIXES[prefix].PREFERRED_LIFETIME,
                                           valid_lifetime=cfg.PREFIXES[prefix].VALID_LIFETIME,
                                           category=cfg.PREFIXES[prefix].CATEGORY,
                                           pclass=cfg.PREFIXES[prefix].CLASS,
                                           ptype=cfg.PREFIXES[prefix].TYPE,
                                           route_link_local=cfg.PREFIXES[prefix].ROUTE_LINK_LOCAL)
                            self.prefixes.append(ia_pd)

            # return client

        except Exception as err:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            log.error('build_client(): ' + str(err))
            return None
