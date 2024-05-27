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

import grp
import os
import pwd
import sys
import traceback

from ..config import cfg
from .store import Store


class SQLite(Store):
    """
        file-based SQLite database, might be an option for single installations
    """
    QUERY_TABLES = "SELECT name FROM sqlite_master WHERE type='table'"

    def __init__(self, query_queue, answer_queue, storage_type='volatile'):

        Store.__init__(self, query_queue, answer_queue)
        self.connection = None

        try:
            self.db_connect(storage_type)
        except:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()

    def db_connect(self, storage_type='volatile'):
        """
        initialize DB connection
        """
        # only import if needed
        if 'sqlite3' not in sys.modules:
            import sqlite3
            self.db_module = sqlite3
        try:
            if storage_type == 'volatile':
                storage = cfg.STORE_SQLITE_VOLATILE
                # set ownership of storage file according to settings
                os.chown(cfg.STORE_SQLITE_VOLATILE, pwd.getpwnam(cfg.USER).pw_uid, grp.getgrnam(cfg.GROUP).gr_gid)
            if storage_type == 'config':
                storage = cfg.STORE_SQLITE_CONFIG
            self.connection = self.db_module.connect(storage, check_same_thread = False)
            self.cursor = self.connection.cursor()
            self.connected = True
        except:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            return None

    def db_query(self, query):
        """
        execute query on DB
        """
        try:
            self.cursor.execute(query)
            # commit only if explicitly wanted
            if query.startswith('INSERT'):
                self.connection.commit()
            elif query.startswith('UPDATE'):
                self.connection.commit()
            elif query.startswith('DELETE'):
                self.connection.commit()
            self.connected = True
        except self.db_module.IntegrityError:
            return 'INSERT_ERROR'
        except Exception as err:
            # try to reestablish database connection
            print(f'Error: {str(err.args[0])}')
            print(f'Query: {query}')
            if not self.db_connect():
                return None

        result = self.cursor.fetchall()
        return result
