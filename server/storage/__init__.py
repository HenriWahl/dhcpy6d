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

import sys
import threading
import traceback

from ..config import cfg
from ..globals import (config_answer_queue,
                       config_query_queue,
                       config_store,
                       volatile_answer_queue,
                       volatile_query_queue,
                       volatile_store)
from ..helpers import error_exit

from .mysql import DBMySQL
from .postgresql import DBPostgreSQL
from .sqlite import SQLite
from .store import (ClientConfig,
                    ClientConfigDB,
                    Store)
from .textfile import Textfile


class QueryQueue(threading.Thread):
    """
    Pump queries around
    """
    def __init__(self, name='', store_type=None, query_queue=None, answer_queue=None):
        threading.Thread.__init__(self, name=name)
        self.query_queue = query_queue
        self.answer_queue = answer_queue
        self.store = store_type
        self.setDaemon(True)

    def run(self):
        """
        receive queries and ask the DB interface for answers which will be put into
        answer queue
        """
        while True:
            query = self.query_queue.get()
            try:
                answer = self.store.db_query(query)
            except Exception as error:
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
                answer = error

            self.answer_queue.put({query: answer})


# because of thread trouble there should not be too much db connections at once
# so we need to use the queryqueue way - subject to change
# source of configuration of hosts
# use client configuration only if needed
if cfg.STORE_CONFIG:
    if cfg.STORE_CONFIG == 'file':
        config_store = Textfile(config_query_queue, config_answer_queue)
    if cfg.STORE_CONFIG == 'mysql':
        config_store = DBMySQL(config_query_queue, config_answer_queue)
    if cfg.STORE_CONFIG == 'postgresql':
        config_store = DBPostgreSQL(config_query_queue, config_answer_queue)
    if cfg.STORE_CONFIG == 'sqlite':
        config_store = SQLite(config_query_queue, config_answer_queue, storage_type='config')
else:
    # dummy configstore if no client config is needed
    config_store = Store(config_query_queue, config_answer_queue)
    # 'none' store is always connected
    config_store.connected = True

# storage for changing data like leases, LLIPs, DUIDs etc.
if cfg.STORE_VOLATILE == 'mysql':
    volatile_store = DBMySQL(volatile_query_queue, volatile_answer_queue)
if cfg.STORE_VOLATILE == 'postgresql':
    volatile_store = DBPostgreSQL(volatile_query_queue, volatile_answer_queue)
if cfg.STORE_VOLATILE == 'sqlite':
    volatile_store = SQLite(volatile_query_queue, volatile_answer_queue, storage_type='volatile')

# do not start if no database connection exists
if not config_store.connected:
    error_exit('Configuration database is not connected!')
if not volatile_store.connected:
    error_exit('Database for volatile data is not connected!')
