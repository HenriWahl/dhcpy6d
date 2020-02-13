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

import random

from ..config import cfg
from ..helpers import (convert_mac_to_eui64,
                       decompress_ip6)
from ..log import log
from ..storage import volatile_store


def parse_pattern_address(address, client_config, transaction):
    """
        parse address pattern and replace variables with current values
    """
    # parse all pattern parts
    a = address.PATTERN

    # if dhcpy6d got a new (mostly dynamic) prefix at start insert it here
    if cfg.PREFIX is not None:
        a = a.replace('$prefix$', cfg.PREFIX)

    # check different client address categories - to be extended!
    if address.CATEGORY == 'mac':
        macraw = ''.join(transaction.mac.split(':'))
        a = a.replace('$mac$', ':'.join((macraw[0:4], macraw[4:8], macraw[8:12])))
    elif address.CATEGORY == 'eui64':
        # https://tools.ietf.org/html/rfc4291#section-2.5.1
        mac = transaction.mac
        a = a.replace('$eui64$', convert_mac_to_eui64(mac))
    elif address.CATEGORY in ['fixed', 'dns']:
        # No patterns for fixed address, let's bail
        return None
    elif address.CATEGORY == 'id':
        # if there is an ID build address
        if str(client_config.ID) != '':
            a = a.replace('$id$', str(client_config.ID))
        else:
            return None
    elif address.CATEGORY == 'random':
        # first check if address already has been advertised
        advertised_address = volatile_store.check_advertised_lease(transaction,
                                                                   category='random',
                                                                   atype=address.TYPE)
        # when address already has been advertised for this client use it
        if advertised_address:
            a = advertised_address
        else:
            ra = str(hex(random.getrandbits(64)))[2:][:-1]
            ra = ':'.join((ra[0:4], ra[4:8], ra[8:12], ra[12:16]))
            # subject to change....
            a = a.replace('$random64$', ra)
    elif address.CATEGORY == 'range':
        range_from, range_to = address.RANGE.split('-')
        if len(range_from) < 4:
            range_from = '0' * (4-len(range_from)) + range_from
        if len(range_to) < 4:
            range_to = '0' * (4-len(range_to)) + range_to
        if range_from > range_to:
            range_from, range_to = range_to, range_from

        # expecting range-range at the last octet, 'prefix' means the first seven octets here
        # - is just shorter than the_first_seven_octets
        prefix = decompress_ip6(a.replace('$range$', '0000'))[:28]

        # the following steps are done to find a collision-free lease in given range
        # check if address already has been advertised - important for REPLY after SOLICIT-ADVERTISE-REQUEST
        advertised_address = volatile_store.check_advertised_lease(transaction, category='range', atype=address.TYPE)
        # when address already has been advertised for this client use it
        if advertised_address:
            a = advertised_address
        else:
            # check if requesting client still has an active lease that could be reused
            lease = volatile_store.get_range_lease_for_recycling(prefix=prefix,
                                                                 range_from=range_from,
                                                                 range_to=range_to,
                                                                 duid=transaction.duid,
                                                                 mac=transaction.mac)
            # the found lease has to be in range - important after changed range boundaries
            if lease is not None and range_from <= lease[28:].lower() <= range_to:
                a = ':'.join((lease[0:4], lease[4:8], lease[8:12], lease[12:16],
                              lease[16:20], lease[20:24], lease[24:28], lease[28:32]))
            else:
                # get highest active lease to increment address about 1
                lease = volatile_store.get_highest_range_lease(prefix=prefix, range_from=range_from, range_to=range_to)
                # check if highest active lease still fits into range
                if lease is not None and range_from <= lease[28:].lower() < range_to:
                    # if highest lease + 1 would not fit range limit is reached
                    if lease[28:].lower() >= range_to:
                        # try to get one of the inactive old leases
                        lease = volatile_store.get_oldest_inactive_range_lease(prefix=prefix,
                                                                               range_from=range_from,
                                                                               range_to=range_to)
                        if lease is None:
                            # if none is available limit is reached and nothing returned
                            log.critical(f'Address space {prefix}[{range_from}-{range_to}] exceeded')
                            return None
                        else:
                            # if lease is OK use it
                            a = lease
                    else:
                        # otherwise increase current maximum range limit by 1
                        a = a.replace('$range$', str(hex(int(lease[28:], 16) + 1)).split('x')[1])
                else:
                    # if there is no lease yet or range limit is reached try to reactivate an old inactive lease
                    lease = volatile_store.get_oldest_inactive_range_lease(prefix=prefix,
                                                                           range_from=range_from,
                                                                           range_to=range_to)
                    if lease is None:
                        # if there are no leases stored yet initiate lease storage
                        # this will be done only once - the first time if there is no other lease yet
                        # so it is safe to start from range_from
                        if volatile_store.check_number_of_leases(prefix, range_from, range_to) <= 1:
                            a = a.replace('$range$', range_from)
                        else:
                            # if none is available limit is reached and nothing returned
                            log.critical(f'Address space {prefix}[{range_from}-{range_to}] exceeded')
                            return None
                    else:
                        # if there is a lease it might be used
                        a = lease

    return decompress_ip6(a)


def parse_pattern_prefix(pattern, client_config, transaction):
    """
        parse address pattern and replace variables with current values
    """
    # parse all pattern parts
    p = pattern.PATTERN

    # if dhcpy6d got a new (mostly dynamic) prefix at start insert it here
    p = p.replace('$prefix$', cfg.PREFIX)

    if pattern.CATEGORY == 'id':
        # if there is an ID build address
        if str(client_config.ID) != '':
            p = p.replace('$id$', str(client_config.ID))
        else:
            return None

    elif pattern.CATEGORY == 'range':
        range_from, range_to = pattern.RANGE.split('-')
        if len(range_from) < 4:
            range_from = '0' * (4-len(range_from)) + range_from
        if len(range_to) < 4:
            range_to = '0' * (4-len(range_to)) + range_to
        if range_from > range_to:
            range_from, range_to = range_to, range_from

        # contrary to addresses the prefix $range$ part of the pattern is expected
        # somewhere at the left part of the pattern
        # here the 128 Bit sum up to 32 characters in address/prefix string so prefix_range_index has to be calculated
        # as first character of range part of prefix - assuming steps of width 4
        prefix_range_index = int(pattern.LENGTH)//4-4
        # prefix itself has a prefix - the first part of the prefix pattern
        prefix_prefix = decompress_ip6(p.replace('$range$', '0000'))[:prefix_range_index]

        # the following steps are done to find a collision-free lease in given range
        # check if address already has been advertised - important for REPLY after SOLICIT-ADVERTISE-REQUEST
        advertised_prefix = volatile_store.check_advertised_prefix(transaction, category='range', ptype=pattern.TYPE)

        # when address already has been advertised for this client use it
        if advertised_prefix:
            p = advertised_prefix
        else:
            # check if requesting client still has an active prefix that could be reused
            prefix = volatile_store.get_range_prefix_for_recycling(prefix=prefix_prefix,
                                                                   length=pattern.LENGTH,
                                                                   range_from=range_from,
                                                                   range_to=range_to,
                                                                   duid=transaction.duid,
                                                                   mac=transaction.mac)
            # the found prefix has to be in range - important after changed range boundaries
            if prefix is not None:
                if range_from <= prefix[prefix_range_index:prefix_range_index+4].lower() <= range_to:
                    p = ':'.join((prefix[0:4], prefix[4:8], prefix[8:12], prefix[12:16],
                                  prefix[16:20], prefix[20:24], prefix[24:28], prefix[28:32]))
                else:
                    # if prefixes are exceeded or something went wrong with from/to ranges return none
                    log.critical('Prefix address space %s[%s-%s] exceeded or something is wrong with from/to ranges' %
                                 (prefix_prefix, range_from, range_to))
                    return None
            else:
                # get highest active lease to increment address about 1
                prefix = volatile_store.get_highest_range_prefix(prefix=prefix_prefix,
                                                                 length=pattern.LENGTH,
                                                                 range_from=range_from,
                                                                 range_to=range_to)
                # check if highest active lease still fits into range
                if prefix is not None:
                    if range_from <= prefix[prefix_range_index:prefix_range_index+4].lower() < range_to:
                        # if highest lease + 1 would not fit range limit is reached
                        if prefix[prefix_range_index:prefix_range_index+4].lower() >= range_to:
                            # try to get one of the inactive old leases
                            prefix = volatile_store.get_oldest_inactive_range_prefix(prefix=prefix_prefix,
                                                                                     length=pattern.LENGTH,
                                                                                     range_from=range_from,
                                                                                     range_to=range_to)
                            if prefix is None:
                                # if none is available limit is reached and nothing returned
                                log.critical(f'Prefix address space {prefix_prefix}[{range_from}-{range_to}] exceeded')
                                return None
                            else:
                                # if lease is OK use it
                                p = prefix
                        else:
                            # otherwise increase current maximum range limit by 1
                            p = p.replace('$range$',
                                          str(hex(int(prefix[prefix_range_index:prefix_range_index+4].lower(), 16)
                                                  + 1)).split('x')[1])

                    else:
                        # if there is no lease yet or range limit is reached try to reactivate an old inactive lease
                        prefix = volatile_store.get_oldest_inactive_range_prefix(prefix=prefix_prefix,
                                                                                 length=pattern.LENGTH,
                                                                                 range_from=range_from,
                                                                                 range_to=range_to)
                        if prefix is None:
                            # if there are no leases stored yet initiate lease storage
                            # this will be done only once - the first time if there is no other lease yet
                            # so it is safe to start from range_from
                            if volatile_store.check_number_of_prefixes(prefix=prefix_prefix,
                                                                       length=pattern.LENGTH,
                                                                       range_from=range_from,
                                                                       range_to=range_to) <= 1:
                                p = p.replace('$range$', range_from)
                            else:
                                # if none is available limit is reached and nothing returned
                                log.critical(
                                    f'Prefix address space {prefix_prefix}[{range_from}-{range_to}] exceeded')
                                return None
                        else:
                            # if there is a lease it might be used
                            p = prefix

                else:
                    # if there is no lease yet or range limit is reached try to reactivate an old inactive lease
                    prefix = volatile_store.get_oldest_inactive_range_prefix(prefix=prefix_prefix,
                                                                             length=pattern.LENGTH,
                                                                             range_from=range_from,
                                                                             range_to=range_to)
                    if prefix is None:
                        # if there are no leases stored yet initiate lease storage
                        # this will be done only once - the first time if there is no other lease yet
                        # so it is safe to start from range_from
                        if volatile_store.check_number_of_prefixes(prefix=prefix_prefix,
                                                                   length=pattern.LENGTH,
                                                                   range_from=range_from,
                                                                   range_to=range_to) <= 1:
                            p = p.replace('$range$', range_from)
                        else:
                            # if none is available limit is reached and nothing returned
                            log.critical(f'Prefix address space {prefix_prefix}[{range_from}-{range_to}] exceeded')
                            return None
                    else:
                        # if there is a lease it might be used
                        p = prefix

    return decompress_ip6(p)
