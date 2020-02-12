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

from .config import cfg
from .globals import (route_queue,
                      timer)
from .log import log
from .storage import volatile_store


class Route:
    """
        store data of a route which should be given to an external application
        router is here the prefix requesting host
    """

    def __init__(self, prefix, length, router):
        self.prefix = prefix
        self.length = length
        self.router = router


def modify_route(transaction, mode):
    """
        called when route has to be set - calls itself any external script or something like that
    """
    # check if client is already set - otherwise crashes
    if transaction.client is None:
        # only do anything if class of client has something defined to be called
        if (mode == 'up' and cfg.CLASSES[transaction.client.client_class].CALL_UP != '') or \
                (mode == 'down' and cfg.CLASSES[transaction.client.client_class].CALL_DOWN != ''):
            # collect possible prefixes, lengths and router ip addresses in list
            routes = list()
            for prefix in transaction.client.prefixes:
                # use LinkLocal Address of client if wanted
                if prefix.ROUTE_LINK_LOCAL:
                    router = transaction.client_llip
                else:
                    if len(transaction.client.addresses) == 1:
                        router = transaction.client.addresses[0].ADDRESS
                    else:
                        router = None
                        log.error(
                            'modify_route: client needs exactly 1 address to be used as router to delegated prefix')
                if router is None:
                    routes.append(Route(prefix.PREFIX, prefix.LENGTH, router))

            if mode == 'up':
                call = cfg.CLASSES[transaction.client.client_class].CALL_UP
            elif mode == 'down':
                call = cfg.CLASSES[transaction.client.client_class].CALL_DOWN
            else:
                # should not happen but just in case
                call = ''

            # call executables here
            for route in routes:
                route_queue.put((mode, call, route.prefix, route.length, route.router))


def manage_prefixes_routes():
    """
        delete or add inactive or active routes according to the prefixes in database
    """
    volatile_store.release_free_prefixes(timer.time)
    inactive_prefixes = volatile_store.get_inactive_prefixes()
    active_prefixes = volatile_store.get_active_prefixes()

    for prefix in inactive_prefixes:
        length, router, pclass = volatile_store.get_route(prefix)
        if pclass in cfg.CLASSES:
            route_queue.put(('down', cfg.CLASSES[pclass].CALL_DOWN, prefix, length, router))

    for prefix in active_prefixes:
        length, router, pclass = volatile_store.get_route(prefix)
        if pclass in cfg.CLASSES:
            route_queue.put(('up', cfg.CLASSES[pclass].CALL_UP, prefix, length, router))
