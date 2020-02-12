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
import traceback

from ..config import cfg
from ..helpers import error_exit

from .store import DB


class DBMySQL(DB):
    """
    access MySQL and Mariadb
    """
    def db_connect(self):
        """
            Connect to database server according to database type
        """
        try:
            if 'MySQLdb' not in list(sys.modules.keys()):
                import MySQLdb
        except:
            error_exit('ERROR: Cannot find module MySQLdb. Please install to proceed.')
        try:
            self.connection = sys.modules['MySQLdb'].connect(host=cfg.STORE_DB_HOST,
                                                             db=cfg.STORE_DB_DB,
                                                             user=cfg.STORE_DB_USER,
                                                             passwd=cfg.STORE_DB_PASSWORD)
            self.connection.autocommit(True)
            self.cursor = self.connection.cursor()
            self.connected = True
        except:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            self.connected = False

        return self.connected

    def db_query(self, query):
        try:
            self.cursor.execute(query)
        except sys.modules['MySQLdb'].IntegrityError:
            return 'IntegrityError'
        except Exception as err:
            # try to reestablish database connection
            print(f'Error: {str(err)}')
            print(f'Query: {query}')
            if not self.db_connect():
                return None
            else:
                try:
                    self.cursor.execute(query)
                except:
                    traceback.print_exc(file=sys.stdout)
                    sys.stdout.flush()
                    self.connected = False
                    return None

        result = self.cursor.fetchall()
        return result
