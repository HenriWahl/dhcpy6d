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

import subprocess
import sys
from threading import Thread
import time
import traceback

import dns

from server.config import cfg
from server.globals import (collected_macs,
                            requests,
                            requests_blacklist,
                            route_queue,
                            resolver_update,
                            transactions,
                            volatile_store)
from server.helpers import colonify_ip6
from server.log import log

class DNSQueryThread(Thread):
    """
        thread for updating DNS entries of valid leases without blocking main thread
    """

    def __init__(self, dnsquery_queue):
        Thread.__init__(self, name='DNSQuery')
        self.setDaemon(1)
        self.dnsquery_queue=dnsquery_queue

    def run(self):
        # wait for new queries in queue until the end of the world
        while True:
            action, hostname, a = self.dnsquery_queue.get()
            # colonify address for DNS
            address = colonify_ip6(a.ADDRESS)
            try:
                # update AAAA record, delete old entry first
                update = dns.update.Update(a.DNS_ZONE, keyring=Keyring)
                update.delete(hostname, 'AAAA')
                # if DNS should be updated do it - not the case if IP is released
                if action == 'update':
                    update.add(hostname, a.DNS_TTL, 'AAAA', address)
                dns.query.tcp(update, cfg.DNS_UPDATE_NAMESERVER)

                # the reverse record will be first checked if it points
                # to the current hostname, if not, it will be deleted first
                update_rev = dns.update.Update(a.DNS_REV_ZONE, keyring=Keyring)
                try:
                    answer = resolver_update.query(dns.reversename.from_address(address), 'PTR')
                    for rdata in answer:
                        hostname_ns = str(rdata).split('.')[0]
                        # if ip address is related to another host delete this one
                        if hostname_ns != hostname:
                            update_rev.delete(dns.reversename.from_address(address), 'PTR', hostname_ns + '.' + a.DNS_ZONE + '.')

                except dns.resolver.NXDOMAIN:
                    pass
                # if DNS should be updated do it - not the case if IP is released
                if action == 'update':
                    update_rev.add(dns.reversename.from_address(address), a.DNS_TTL, 'PTR', hostname + '.' + a.DNS_ZONE + '.')
                elif action == 'release':
                    update_rev.delete(dns.reversename.from_address(address), 'PTR')
                dns.query.tcp(update_rev, cfg.DNS_UPDATE_NAMESERVER)
            except Exception as err:
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
                log.error('DNSUPDATE: ' + str(err))


class TidyUpThread(Thread):
    """
        clean leases and transactions if obsolete
    """
    def __init__(self):
        Thread.__init__(self, name='TidyUp')
        self.setDaemon(1)

    def run(self):
        try:
            # counter for database cleaning interval
            dbcount = 0

            # get and delete invalid leases
            while True:
                # transaction data can be deleted after transaction is finished
                for t in list(transactions.keys()):
                    try:
                        if timer > transactions[t].Timestamp + cfg.CLEANING_INTERVAL * 10:
                            transactions.pop(transactions[t].ID)
                    except Exception as err:
                        log.error('TidyUp: TransactionID %s has already been deleted' % (str(err)))
                        traceback.print_exc(file=sys.stdout)
                        sys.stdout.flush()

                # if disconnected try reconnect
                if not volatile_store.connected:
                    volatile_store.DBConnect()
                else:
                    # cleaning database once per minute should be enough
                    if dbcount > 60//cfg.CLEANING_INTERVAL:
                        # remove leases which might not be recycled like random addresses for example
                        volatile_store.remove_leases(timer, 'random')
                        # set leases and prefixes free whose valid lifetime is over
                        volatile_store.release_free_leases(timer)
                        volatile_store.release_free_prefixes(timer)
                        # unlock advertised leases and prefixes remaining
                        volatile_store.unlock_unused_advertised_leases(timer)
                        volatile_store.unlock_unused_advertised_prefixes(timer)
                        # remove routes with inactive prefixes
                        self.check_routes()
                        # check for brute force clients and put them into blacklist if necessary
                        self.check_requests(timer)
                        dbcount = 0
                dbcount += 1

                # clean collected MAC addresses after 300 seconds
                # some Linuxes seem to be pretty slow and run out of the previous 30 seconds
                if cfg.CACHE_MAC_LLIP == False:
                    timestamp = timer
                    for record in list(collected_macs.values()):
                        if record.timestamp + 60 * cfg.CLEANING_INTERVAL < timestamp:
                            if cfg.LOG_MAC_LLIP:
                                log.info('Deleted MAC %s for LinkLocalIP %s' % (record.mac, colonify_ip6(record.llip)))
                            collected_macs.pop(record.llip)
                    del timestamp
                time.sleep(cfg.CLEANING_INTERVAL)
        except:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()


    def check_routes(self):
        """
            remove routes with inactive prefixes
        """
        for prefix in volatile_store.get_inactive_prefixes():
            length, router, pclass = volatile_store.get_route(prefix)
            # hopefully the class stored in database still exists
            if pclass in cfg.CLASSES:
                route_queue.put(('down', cfg.CLASSES[pclass].CALL_DOWN, prefix, length, router))


    def check_requests(self, now):
        """
            check for brute force clients and put them into blacklist if necessary
            get time as now from caller
        """

        # clean blacklist
        for client in list(requests_blacklist.keys()):
            if now > requests_blacklist[client].timestamp + cfg.REQUEST_LIMIT_RELEASE_TIME:
                log.info("Releasing client {0} from blacklist".format(client))
                requests_blacklist.pop(client)

        # clean default requests list
        for client in list(requests.keys()):
            if now > requests[client].timestamp + cfg.REQUEST_LIMIT_TIME:
                if requests[client].count > cfg.REQUEST_LIMIT_COUNT:
                    log.info("Blacklisting client {0} after {1} requests".format(client, requests[client].count))
                    requests_blacklist[client] = requests.pop(client)
                else:
                    requests.pop(client)


class RouteThread(Thread):
    """
        thread for updating routes without blocking main thread
    """

    def __init__(self, route_queue):
        Thread.__init__(self, name='Route')
        self.setDaemon(1)
        self.route_queue=route_queue


    def run(self):
        """
            wait for new queries in queue until the end of the world
        """
        while True:
            mode, call, prefix, length, router = self.route_queue.get()
            call_real = call.replace('$prefix$', colonify_ip6(prefix)).\
                             replace('$length$', str(length)).\
                             replace('$router$', colonify_ip6(router))
            # subprocess needs list as argument which it gets by split()
            try:
                result = subprocess.call(call_real.split(' '))
            except Exception as err:
                result = err
            # ignore result to avoid routes being set but not noted in database when a command like
            # 'ip -6 route delete' gives a return code not 0 because a route already exists
            if mode == 'up':
                volatile_store.store_route(prefix, length, router, timer)
            if mode == 'down':
                volatile_store.remove_route(prefix)
            log.info("Called '{0}' to modify route - result: {1}".format(call_real, result))


class TimerThread(Thread):
    """
        thread for timer, used in different places
    """

    def __init__(self):
        Thread.__init__(self, name='Timer')
        self.setDaemon(1)

    def run(self):
        global timer
        while True:
            timer = int(time.time())
            time.sleep(1)
