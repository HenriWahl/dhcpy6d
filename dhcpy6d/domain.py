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

import copy

from dns.resolver import (NoAnswer,
                          NoNameservers)

from .config import cfg
from .globals import (dns_query_queue,
                      resolver_query)
from .helpers import decompress_ip6
from .storage import volatile_store


def dns_update(transaction, action='update'):
    """
        update DNS entries on specified nameserver
        at the moment this only works with Bind
        uses all addresses of client if they want to be dynamically updated

        regarding RFC 4704 5. there are 3 kinds of client behaviour for N O S:
        - client wants to update DNS itself -> sends 0 0 0
        - client wants server to update DNS -> sends 0 0 1
        - client wants no server DNS update -> sends 1 0 0
    """
    if transaction.client:
        # if allowed use client supplied hostname, otherwise that from config
        if cfg.DNS_USE_CLIENT_HOSTNAME:
            # hostname from transaction
            hostname = transaction.hostname
        else:
            # hostname from client info built from configuration
            hostname = transaction.client.hostname

        # if address should be updated in DNS update it
        for a in transaction.client.addresses:
            if a.DNS_UPDATE and hostname != '' and a.VALID:
                if cfg.DNS_IGNORE_CLIENT or transaction.dns_s == 1:
                    # put query into DNS query queue
                    dns_query_queue.put((action, hostname, a))
        return True
    else:
        return False


def dns_delete(transaction, address='', action='release'):
    """
        delete DNS entries on specified nameserver
        at the moment this only works with ISC Bind
    """
    hostname, duid, mac, iaid = volatile_store.get_host_lease(address)

    # if address should be updated in DNS update it
    # local flag to check if address should be deleted from DNS
    delete = False

    for a in list(cfg.ADDRESSES.values()):
        # if there is any address type which prototype matches use its DNS ZONE
        if a.matches_prototype(address):
            # kind of RCF-compliant security measure - check if hostname and DUID from transaction fits them of store
            if duid == transaction.duid and \
               iaid == transaction.iaid:
                delete = True
                # also check MAC address if MAC counts in general - not RFCish
                if 'mac' in cfg.IDENTIFICATION:
                    if not mac == transaction.mac:
                        delete = False

            if hostname != '' and delete:
                # use address from address types as template for the real
                # address to be deleted from DNS
                dns_address = copy.copy(a)
                dns_address.ADDRESS = address
                # put query into DNS query queue
                dns_query_queue.put((action, hostname, dns_address))
            # enough
            break


def get_ip_from_dns(hostname):
    """
        Get IPv6 address from DNS for address category 'dns'
    """
    try:
        answer = resolver_query.query(hostname, 'AAAA')
        return decompress_ip6(answer.rrset.to_text().split(' ')[-1])
    except NoAnswer:
        return False
    except NoNameservers:
        return False
