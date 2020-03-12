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

from .schemas import POSTGRESQL_SCHEMA
from .store import DB


class DBPostgreSQL(DB):
    """
    PostgreSQL connection - to be tested!
    """
    schemas = POSTGRESQL_SCHEMA

    def db_connect(self):
        """
            Connect to database server according to database type
        """
        try:
            if 'psycopg2' not in list(sys.modules.keys()):
                import psycopg2
                self.db_module = psycopg2
        except:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            error_exit('ERROR: Cannot find module psycopg2. Please install to proceed.')
        try:
            self.connection = self.db_module.connect(host=cfg.STORE_DB_HOST,
                                                              database=cfg.STORE_DB_DB,
                                                              user=cfg.STORE_DB_USER,
                                                              password=cfg.STORE_DB_PASSWORD)
            self.connection.autocommit = True
            self.cursor = self.connection.cursor()
            self.connected = True
        except:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            self.connected = False
        return self.connected

    def db_query_bla(self, query):
        try:
            self.cursor.execute(query)
        except (self.db_module.errors.UndefinedTable,
                self.db_module.errors.DuplicateTable) as err:
            err_msg = err.diag.message_primary
            # try to reestablish database connection
            print(f'Error: {err_msg}')
            print(f'Query: {query}')
            if not self.db_connect():
                return None
            else:
                try:
                    # build tables if they are not existing yet
                    if err_msg.startswith('relation "') and err_msg.endswith('" does not exist'):
                        table = err_msg.split('"')[1]
                        #self.cursor.execute(self.schemas[table])
                    # if they already exist just execute some dummy query - can't be empty in PostgreSQL
                    elif (err_msg.startswith('relation "') and err_msg.endswith('" already exists')):
                        self.cursor.execute("SELECT 'dummy'")
                    else:
                        self.cursor.execute(query)
                except:
                    traceback.print_exc(file=sys.stdout)
                    sys.stdout.flush()
                    self.connected = False
                    return None
        except self.db_module.errors.UniqueViolation as err:
            # key can't be inserted twice
            print(f'Error: {err.diag.message_primary}')
            print(f'Query: {query}')
            return None
        except Exception as err:
            # try to reestablish database connection
            print(f'Error: {str(err.args[0])}')
            print(f'Query: {query}')
            if not self.db_connect():
                return None
        try:
            result = self.cursor.fetchall()
        # quite probably a psycopg2.ProgrammingError occurs here
        # which should be caught by except psycopg2.ProgrammingError
        # but psycopg2 is not known here
        except Exception:
            return None
        return result

    def db_query(self, query):
        try:
            self.cursor.execute(query)
        except Exception as err:
            # try to reestablish database connection
            print(f'Error: {str(err)}')
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
        try:
            result = self.cursor.fetchall()
        # quite probably a psycopg2.ProgrammingError occurs here
        # which should be caught by except psycopg2.ProgrammingError
        # but psycopg2 is not known here
        except Exception:
            return None
        return result

    def get_tables(self):
        """
        return tables - no turntables
        """
        tables = []
        query = f"select table_name from information_schema.tables WHERE " \
                f"table_schema = 'public' AND " \
                f"table_catalog = '{cfg.STORE_DB_DB}'"
        answer = self.query(query)
        if len(answer) > 0:
            tables = [x[0] for x in answer]
        return tables
