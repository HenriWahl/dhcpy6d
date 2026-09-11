# DHCPy6d DHCPv6 Daemon
#
# Copyright (C) 2009-2024 Henri Wahl <henri@dhcpy6d.de>
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

import atexit
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
                    ClientConfigDicts,
                    Store)
from .textfile import Textfile


class AsyncQuery:
    """A query whose result is intentionally not returned to a caller."""
    def __init__(self, query, callback=None):
        self.query = query
        self.callback = callback


class AsyncBatch:
    """A write batch whose backend controls transactional execution."""
    def __init__(self, queries, callback=None):
        self.queries = queries
        self.callback = callback


class AsyncStore:
    """A complete lease-store operation run by the database worker."""
    def __init__(self, transaction, now, callback=None):
        self.transaction = transaction
        self.now = now
        self.callback = callback


class QueryQueue(threading.Thread):
    """
    Pump queries around
    """
    def __init__(self, name='', store_type=None, query_queue=None, answer_queue=None):
        threading.Thread.__init__(self, name=name)
        self.query_queue = query_queue
        self.answer_queue = answer_queue
        self.store = store_type
        self.daemon = True

    def run(self):
        """
        receive queries and ask the DB interface for answers which will be put into
        answer queue
        """
        while True:
            queued_query = self.query_queue.get()
            async_query = isinstance(queued_query, AsyncQuery)
            async_batch = isinstance(queued_query, AsyncBatch)
            async_store = isinstance(queued_query, AsyncStore)
            query = queued_query.query if async_query else queued_query
            try:
                if async_store:
                    answer = self.store.store(queued_query.transaction, queued_query.now,
                                              query_function=self.store.db_query,
                                              batch_function=self.store.db_query_batch)
                elif async_batch:
                    answer = self.store.db_query_batch(queued_query.queries)
                else:
                    answer = self.store.db_query(query)
            except Exception as error:
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
                answer = error

            if not async_query and not async_batch and not async_store:
                self.answer_queue.put({query: answer})
            elif queued_query.callback is not None:
                queued_query.callback(answer)


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
    # set client config schema version after config storage is established
    config_store.set_client_config_schema_version(cfg.STORE_CONFIG_SCHEMA_VERSION)
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


def close_stores():
    """
    Close import-time storage connections during interpreter shutdown.
    """
    seen = set()
    for store in (config_store, volatile_store):
        if id(store) in seen:
            continue
        seen.add(id(store))
        close = getattr(store, 'close', None)
        if close is not None:
            close()


atexit.register(close_stores)
