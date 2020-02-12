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
from ..domain import get_ip_from_dns

from .parse_pattern import (parse_pattern_address,
                            parse_pattern_prefix)


def default(client=None, client_config=None, transaction=None):
    # use default class if host is unknown
    client.hostname = transaction.hostname
    client.client_class = 'default_' + transaction.interface
    # apply answer type of client to transaction - useful if no answer or no address available is configured
    transaction.answer = cfg.CLASSES[client.client_class].ANSWER

    if 'addresses' in cfg.CLASSES['default_' + transaction.interface].ADVERTISE and \
            (3 or 4) in transaction.ia_options:
        for address in cfg.CLASSES['default_' + transaction.interface].ADDRESSES:
            # addresses of category 'dns' will be searched in DNS
            if cfg.ADDRESSES[address].CATEGORY == 'dns':
                a = get_ip_from_dns(client.hostname)
            else:
                a = parse_pattern_address(cfg.ADDRESSES[address], client, transaction)
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
                client.addresses.append(ia)

    if 'prefixes' in cfg.CLASSES['default_' + transaction.interface].ADVERTISE and \
            CONST.OPTION.IA_PD in transaction.ia_options:

        for prefix in cfg.CLASSES['default_' + transaction.interface].PREFIXES:
            p = parse_pattern_prefix(cfg.PREFIXES[prefix], client_config, transaction)
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
                client.prefixes.append(ia_pd)

    # given client has been modified successfully
    return True
