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


def from_config(client=None, client_config=None, transaction=None):
    # give client hostname + class
    client.hostname = client_config.HOSTNAME
    client.client_class = client_config.CLASS
    # apply answer type of client to transaction - useful if no answer or no address available is configured
    transaction.answer = cfg.CLASSES[client.client_class].ANSWER
    # continue only if request interface matches class interfaces
    if transaction.interface in cfg.CLASSES[client.client_class].INTERFACE:
        # if fixed addresses are given build them
        if client_config.ADDRESS is not None:
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
                    client.addresses.append(ia)

        if not client_config.CLASS == '':
            # add all addresses which belong to that class
            for address in cfg.CLASSES[client_config.CLASS].ADDRESSES:
                # addresses of category 'dns' will be searched in DNS
                if cfg.ADDRESSES[address].CATEGORY == 'dns':
                    a = get_ip_from_dns(client.hostname)
                else:
                    a = parse_pattern_address(cfg.ADDRESSES[address], client_config, transaction)
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
                    client.addresses.append(ia)

            # add all bootfiles which belong to that class
            for bootfile in cfg.CLASSES[client_config.CLASS].BOOTFILES:
                client_architecture = cfg.BOOTFILES[bootfile].CLIENT_ARCHITECTURE
                user_class = cfg.BOOTFILES[bootfile].USER_CLASS

                # check if transaction attributes matches the bootfile defintion
                if (not client_architecture or
                    transaction.client_architecture == client_architecture or
                    transaction.known_client_architecture == client_architecture) and \
                        (not user_class or
                         transaction.UserClass == user_class):
                    client.bootfiles.append(cfg.BOOTFILES[bootfile])

            if 'prefixes' in cfg.CLASSES[client_config.CLASS].ADVERTISE and \
                    CONST.OPTION.IA_PD in transaction.ia_options:
                for prefix in cfg.CLASSES[client_config.CLASS].PREFIXES:
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

        if client_config.ADDRESS == client_config.CLASS == '':
            # use default class if no class or address is given
            for address in cfg.CLASSES['default_' + transaction.interface].ADDRESSES:
                client.client_class = 'default_' + transaction.interface
                # addresses of category 'dns' will be searched in DNS
                if cfg.ADDRESSES[address].CATEGORY == 'dns':
                    a = get_ip_from_dns(client.hostname)
                else:
                    a = parse_pattern_address(cfg.ADDRESSES[address], client_config, transaction)
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

            for bootfile in cfg.CLASSES['default_' + transaction.interface].BOOTFILES:
                client_architecture = bootfile.CLIENT_ARCHITECTURE
                user_class = bootfile.USER_CLASS

                # check if transaction attributes matches the bootfile defintion
                if (not client_architecture or
                    transaction.client_architecture == client_architecture or
                    transaction.known_client_architecture == client_architecture) and \
                        (not user_class or
                         transaction.UserClass == user_class):
                    client.bootfiles.append(bootfile)

    # given client has been modified successfully
    return True
