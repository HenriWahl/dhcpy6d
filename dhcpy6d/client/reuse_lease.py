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

from ..config import (Address,
                      cfg,
                      Prefix)
from ..constants import CONST
from ..globals import timer
from ..helpers import (decompress_ip6,
                       decompress_prefix,
                       split_prefix)
from ..storage import volatile_store

from .parse_pattern import parse_pattern_address


def reuse_lease(client=None, client_config=None, transaction=None):
    """
    Reuse already existing lease information
    """
    if client_config is not None:
        # give client hostname
        client.hostname = client_config.HOSTNAME
        client.client_class = client_config.CLASS
        # apply answer type of client to transaction - useful if no answer or no address available is configured
        transaction.answer = cfg.CLASSES[client.client_class].ANSWER
    else:
        # use default class if host is unknown
        client.hostname = transaction.hostname
        client.client_class = 'default_' + transaction.interface
        # apply answer type of client to transaction - useful if no answer or no address available is configured
        transaction.answer = cfg.CLASSES[client.client_class].ANSWER

    if 'addresses' in cfg.CLASSES[client.client_class].ADVERTISE and \
            (CONST.OPTION.IA_NA or CONST.OPTION.IA_TA) in transaction.ia_options:
        for address in transaction.addresses:
            # check_lease returns hostname, address, type, category, ia_type, class, preferred_until of leased address
            answer = volatile_store.check_lease(address, transaction)
            if answer:
                if len(answer) > 0:
                    for item in answer:
                        a = dict(list(
                            zip(('hostname', 'address', 'type', 'category', 'ia_type', 'class', 'preferred_until'),
                                item)))
                        # if lease exists but no configured client set class to default
                        if client_config is None:
                            client.hostname = transaction.hostname
                            client.client_class = 'default_' + transaction.interface
                        # check if address type of lease still exists in configuration
                        # and if request interface matches that of class
                        if a['class'] in cfg.CLASSES and client.client_class == a['class'] and \
                                transaction.interface in cfg.CLASSES[client.client_class].INTERFACE:
                            # type of address must be defined in addresses for this class
                            # or fixed/dns - in which case it is not class related
                            if a['type'] in cfg.CLASSES[a['class']].ADDRESSES or a['type'] in ['fixed']:
                                # flag for lease usage
                                use_lease = True
                                # test lease validity against address prototype pattern only if not fixed or from DNS
                                if not a['category'] in ['fixed', 'dns']:
                                    # test if address matches pattern
                                    for identification in range(len(address)):
                                        if address[identification] != cfg.ADDRESSES[a['type']].PROTOTYPE[
                                            identification] and \
                                                cfg.ADDRESSES[a['type']].PROTOTYPE[identification] != 'x':
                                            use_lease = False
                                            break
                                elif a['category'] == 'fixed' and client_config.ADDRESS is not None:
                                    if address not in client_config.ADDRESS:
                                        use_lease = False
                                elif a['category'] == 'dns':
                                    use_lease = False

                                # only use lease if it still matches prototype
                                if use_lease:
                                    # when category is range, test if it still applies
                                    if a['category'] == 'range':
                                        # borrowed from parse_pattern_address to find out if lease is still in
                                        # a meanwhile maybe changed range
                                        range_from, range_to = cfg.ADDRESSES[a['type']].RANGE.split('-')

                                        # correct possible misconfiguration
                                        if len(range_from) < 4:
                                            range_from = '0' * (4 - len(range_from)) + range_from
                                        if len(range_to) < 4:
                                            range_to = '0' * (4 - len(range_to)) + range_to
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
                                            client.addresses.append(ia)

                                    # de-preferred random address has to be deleted and replaced
                                    elif a['category'] == 'random' and timer.time > a['preferred_until']:
                                        # create new random address if old one is depreferred
                                        random_address = parse_pattern_address(cfg.ADDRESSES[a['type']],
                                                                               client_config,
                                                                               transaction)
                                        # create new random address if old one is de-preferred
                                        # do not wait until it is invalid
                                        if random_address is not None:
                                            ia = Address(address=random_address,
                                                         ia_type=cfg.ADDRESSES[a['type']].IA_TYPE,
                                                         preferred_lifetime=cfg.ADDRESSES[a['type']].PREFERRED_LIFETIME,
                                                         valid_lifetime=cfg.ADDRESSES[a['type']].VALID_LIFETIME,
                                                         category='random',
                                                         aclass=cfg.ADDRESSES[a['type']].CLASS,
                                                         atype=cfg.ADDRESSES[a['type']].TYPE,
                                                         dns_update=cfg.ADDRESSES[a['type']].DNS_UPDATE,
                                                         dns_zone=cfg.ADDRESSES[a['type']].DNS_ZONE,
                                                         dns_rev_zone=cfg.ADDRESSES[a['type']].DNS_REV_ZONE,
                                                         dns_ttl=cfg.ADDRESSES[a['type']].DNS_TTL)
                                            client.addresses.append(ia)
                                            # set de-preferred address invalid
                                            client.addresses.append(Address(address=a['address'],
                                                                            valid=False,
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
                                        client.addresses.append(ia)

        # important indent here, has to match for...addresses-loop!
        # look for addresses in transaction that are invalid and add them
        # to client addresses with flag invalid and a RFC-compliant lifetime of 0
        for a in set(transaction.addresses).difference(
                [decompress_ip6(x.ADDRESS) for x in client.addresses]):
            client.addresses.append(Address(address=a,
                                            valid=False,
                                            preferred_lifetime=0,
                                            valid_lifetime=0))

    if 'prefixes' in cfg.CLASSES[client.client_class].ADVERTISE and \
            CONST.OPTION.IA_PD in transaction.ia_options:
        for prefix in transaction.prefixes:
            # split prefix of prefix from length, separated by /
            prefix_prefix, prefix_length = split_prefix(prefix)

            # check_prefix returns hostname, prefix, length, type, category, class, preferred_until of leased address
            answer = volatile_store.check_prefix(prefix_prefix, prefix_length, transaction)

            if answer:
                if len(answer) > 0:
                    for item in answer:
                        p = dict(list(
                            zip(('hostname', 'prefix', 'length', 'type', 'category', 'class', 'preferred_until'),
                                item)))
                        # if lease exists but no configured client set class to default
                        if client_config is None:
                            client.hostname = transaction.hostname
                            client.client_class = 'default_' + transaction.interface
                        # check if address type of lease still exists in configuration
                        # and if request interface matches that of class
                        if p['class'] in cfg.CLASSES and client.client_class == p['class'] and \
                                transaction.interface in cfg.CLASSES[client.client_class].INTERFACE:
                            # type of address must be defined in addresses for this class
                            # or fixed/dns - in which case it is not class related
                            if p['type'] in cfg.CLASSES[p['class']].PREFIXES:
                                # flag for lease usage
                                use_lease = True
                                # test if prefix matches pattern
                                for identification in range(len(prefix_prefix)):
                                    if prefix_prefix[identification] != cfg.PREFIXES[p['type']].PROTOTYPE[
                                        identification] and \
                                            cfg.PREFIXES[p['type']].PROTOTYPE[identification] != 'x':
                                        use_lease = False
                                        break
                                # only use prefix if it still matches prototype
                                if use_lease:
                                    # when category is range, test if it still applies
                                    if p['category'] == 'range':
                                        # borrowed from parse_pattern_prefix to find out if lease
                                        # is still in a meanwhile maybe changed range
                                        range_from, range_to = cfg.PREFIXES[p['type']].RANGE.split('-')

                                        # correct possible misconfiguration
                                        if len(range_from) < 4:
                                            range_from = '0' * (4 - len(range_from)) + range_from
                                        if len(range_to) < 4:
                                            range_to = '0' * (4 - len(range_to)) + range_to
                                        if range_from > range_to:
                                            range_from, range_to = range_to, range_from

                                        # contrary to addresses the prefix $range$ part of the pattern is expected
                                        # somewhere at the left part of the pattern
                                        # here the 128 Bit sum up to 32 characters in address/prefix string so
                                        # prefix_range_index has to be calculated as first character of range part of
                                        # prefix - assuming steps of width 4
                                        prefix_range_index = int(cfg.PREFIXES[p['type']].LENGTH) // 4 - 4
                                        # prefix itself has a prefix - the first part of the prefix pattern
                                        prefix_prefix = decompress_ip6(p['prefix'].replace('$range$', '0000'))[
                                                        :prefix_range_index + 4]

                                        # if lease is still inside range boundaries use it
                                        if range_from <= prefix_prefix[
                                                         prefix_range_index:prefix_range_index + 4].lower() < range_to:
                                            # build IA partly of leases db, partly of config db
                                            ia = Prefix(prefix=p['prefix'],
                                                        length=p['length'],
                                                        ptype=p['type'],
                                                        preferred_lifetime=cfg.PREFIXES[p['type']].PREFERRED_LIFETIME,
                                                        valid_lifetime=cfg.PREFIXES[p['type']].VALID_LIFETIME,
                                                        category=p['category'],
                                                        pclass=p['class'],
                                                        route_link_local=cfg.PREFIXES[p['type']].ROUTE_LINK_LOCAL)
                                            client.prefixes.append(ia)

        # important indent here, has to match for...prefixes-loop!
        # look for prefixes in transaction that are invalid and add them
        # to client prefixes with flag invalid and a RFC-compliant lifetime of 0
        if len(client.prefixes) > 0:
            for p in set(transaction.prefixes).difference(
                    [decompress_prefix(x.PREFIX, x.LENGTH) for x in client.prefixes]):
                prefix, length = split_prefix(p)
                client.prefixes.append(Prefix(prefix=prefix,
                                              length=length,
                                              valid=False,
                                              preferred_lifetime=0,
                                              valid_lifetime=0))
                del (prefix, length)

    # given client has been modified successfully
    return True
