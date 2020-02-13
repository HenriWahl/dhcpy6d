#!/usr/bin/env python3
# encoding: utf8
#
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

import distro
import sys

# access /usr/share/pyshared on Debian
# http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=715010

if distro.id() == 'debian':
    sys.path[0:0] = ['/usr/share/pyshared']

import grp
import pwd
import os
import socket

from dhcpy6d import UDPMulticastIPv6
from dhcpy6d.config import cfg

from dhcpy6d.globals import (config_answer_queue,
                             config_query_queue,
                             IF_NAME,
                             route_queue,
                             volatile_answer_queue,
                             volatile_query_queue)
from dhcpy6d.log import log
from dhcpy6d.handler import RequestHandler

from dhcpy6d.route import manage_prefixes_routes
from dhcpy6d.storage import (config_store,
                             QueryQueue,
                             volatile_store)
from dhcpy6d.threads import (DNSQueryThread,
                             RouteThread,
                             TidyUpThread,
                             TimerThread)

# main part, initializing all stuff

if __name__ == '__main__':
    log.info('Starting dhcpy6d daemon...')
    log.info(f'Server DUID: {cfg.SERVERDUID}')

    # configure SocketServer
    UDPMulticastIPv6.address_family = socket.AF_INET6
    udp_server = UDPMulticastIPv6(('', 547), RequestHandler)

    # start query queue watcher
    config_query_queue_watcher = QueryQueue(name='config_query_queue',
                                            store_type=config_store,
                                            query_queue=config_query_queue,
                                            answer_queue=config_answer_queue)
    config_query_queue_watcher.start()
    volatile_query_queue_watcher = QueryQueue(name='volatile_query_queue',
                                              store_type=volatile_store,
                                              query_queue=volatile_query_queue,
                                              answer_queue=volatile_answer_queue)
    volatile_query_queue_watcher.start()

    # if global dynamic prefix was not given take it from database - only possible after database initialisation
    if cfg.PREFIX == '':
        cfg.PREFIX = volatile_store.get_dynamic_prefix()
    if cfg.PREFIX is None:
        cfg.PREFIX = ''

    # apply dynamic prefix to addresses and prefixes
    for a in cfg.ADDRESSES:
        cfg.ADDRESSES[a].inject_dynamic_prefix_into_prototype(cfg.PREFIX)
    for p in cfg.PREFIXES:
        cfg.PREFIXES[p].inject_dynamic_prefix_into_prototype(cfg.PREFIX)

    # adjust old data to match newer versions of dhcpy6d
    volatile_store.legacy_adjustments()

    # collect all known MAC addresses from database
    if cfg.CACHE_MAC_LLIP:
        volatile_store.collect_macs_from_db()

    # start timer
    timer_thread = TimerThread()
    timer_thread.start()

    # start route queue to care for routes in background
    route_thread = RouteThread(route_queue)
    route_thread.start()

    # delete invalid and add valid routes - useful after reboot
    if cfg.MANAGE_ROUTES_AT_START:
        manage_prefixes_routes()

    # start TidyUp thread for cleaning in background
    tidyup_thread = TidyUpThread()
    tidyup_thread.start()

    # start DNS query queue to care for DNS in background
    dns_query_thread = DNSQueryThread()
    dns_query_thread.start()

    # set user and group
    log.info(f'Running as user {cfg.USER} (UID {pwd.getpwnam(cfg.USER).pw_uid}) and '
             f'group {cfg.GROUP} (GID {grp.getgrnam(cfg.GROUP).gr_gid})')
    # first set group because otherwise the freshly unprivileged user could not modify its groups itself
    os.setgid(grp.getgrnam(cfg.GROUP).gr_gid)
    os.setuid(pwd.getpwnam(cfg.USER).pw_uid)

    # log interfaces
    log.info(f'Listening on interfaces: {" ".join(IF_NAME)}')

    # serve forever
    try:
        udp_server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
