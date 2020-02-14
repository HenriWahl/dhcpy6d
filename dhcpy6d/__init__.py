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

"""Module dhcpy6d"""

import socket
import socketserver
import struct

from .config import cfg
from .globals import (collected_macs,
                      IF_NAME,
                      IF_NUMBER,
                      NC,
                      OS,
                      timer)
from .helpers import (colonify_ip6,
                      colonify_mac,
                      correct_mac,
                      decompress_ip6,
                      NeighborCacheRecord)
from .log import log
from .storage import volatile_store


class UDPMulticastIPv6(socketserver.UnixDatagramServer):
    """
        modify server_bind to work with multicast
        add DHCPv6 multicast group ff02::1:2
    """
    def server_bind(self):
        """
            multicast & python: http://code.activestate.com/recipes/442490/
        """
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # multicast parameters
        # hop is one because it is all about the same subnet
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)

        for i in cfg.INTERFACE:
            # IF_NAME[i] = LIBC.if_nametoindex(i)
            IF_NAME[i] = socket.if_nametoindex(i)
            IF_NUMBER[IF_NAME[i]] = i
            if_number = struct.pack('I', IF_NAME[i])
            mgroup = socket.inet_pton(socket.AF_INET6, cfg.MCAST) + if_number

            # join multicast group - should work definitively if not ignoring interface at startup
            if cfg.IGNORE_INTERFACE:
                try:
                    self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mgroup)
                except Exception as err:
                    print(err)
            else:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mgroup)

        # bind socket to server address
        self.socket.bind(self.server_address)

        # attempt to avoid blocking
        self.socket.setblocking(False)

        # some more requests?
        self.request_queue_size = 100
