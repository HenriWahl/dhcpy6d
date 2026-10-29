"""Startup reconciliation with real SQLite lease rows and textfile client config."""
# Support both unittest discovery layouts and initialize daemon imports first.
if __package__:
    from . import test_prefix_substitution
else:
    import test_prefix_substitution
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dhcpy6d.config import cfg
from dhcpy6d.globals import route_queue, timer
from dhcpy6d.storage.store import Store
from dhcpy6d.storage.textfile import Textfile
from dhcpy6d import route

PREFIX = '20010db8001000b00000000000000000'
MAC = '02:00:00:00:00:02'


class FixedRouteStartupTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE prefixes (prefix TEXT PRIMARY KEY, length INTEGER, active INTEGER,
                hostname TEXT, type TEXT, category TEXT, class TEXT, mac TEXT, duid TEXT,
                valid_until INTEGER, last_message INTEGER);
            CREATE TABLE routes (prefix TEXT PRIMARY KEY, length INTEGER, router TEXT, last_update INTEGER);
        """)
        columns = [row[1] for row in self.db.execute('pragma table_info(prefixes)')]
        values = dict.fromkeys(columns, 0)
        values.update(prefix=PREFIX, length=60, active=1, hostname='client',
                      type='default', category='range', **{'class': 'fixed_lan'},
                      mac=MAC, duid='0001000100000000000000000002', valid_until=1000)
        self.db.execute('insert into prefixes values (' + ','.join('?' for _ in columns) + ')',
                        [values[col] for col in columns])
        self.db.execute('insert into routes values (?,60,?,0)',
                        (PREFIX, 'fe800000000000000000000000000002'))
        self.store = Store(None, None)
        self.store.query = lambda sql: self.db.execute(sql).fetchall()
        self.client_file = Path(self.temp.name) / 'clients.conf'
        self.patches = [patch.object(cfg, 'STORE_CONFIG', 'file'),
                        patch.object(cfg, 'STORE_FILE_CONFIG', str(self.client_file)),
                        patch.object(cfg, 'IDENTIFICATION', ['mac']),
                        patch.object(cfg, 'IDENTIFICATION_MODE', 'match_all'),
                        patch.object(cfg, 'CLASSES', {'fixed_lan': SimpleNamespace(
                            PREFIXES=[], ADDRESSES=[], CALL_UP='add', CALL_DOWN='del')}),
                        patch.object(route, 'volatile_store', self.store)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        timer.time = 100
        self.configure()
        self.clear_queue()
        self.addCleanup(self.clear_queue)

    @staticmethod
    def clear_queue():
        while not route_queue.empty():
            route_queue.get_nowait()

    def configure(self, prefix='2001:db8:10:b0::/60', mac=MAC, client_class='fixed_lan'):
        self.client_file.write_text('[client]\nhostname = client\nmac = ' + mac +
                                   '\nclass = ' + client_class + '\nprefix = ' + prefix + '\n')
        self.config = Textfile(None, None)

    def reconcile(self):
        with patch.object(route, 'config_store', self.config):
            route.manage_prefixes_routes()
        return [route_queue.get_nowait() for _ in range(route_queue.qsize())]

    def test_legacy_fixed_assignment_is_retained_on_repeated_startup(self):
        for _ in range(2):
            self.assertEqual([event[0] for event in self.reconcile()], ['up'])
            self.assertEqual(self.db.execute('select active from prefixes').fetchone(), (1,))
            self.assertEqual(self.db.execute('select count(*) from routes').fetchone(), (1,))

    def test_new_fixed_metadata_is_retained(self):
        self.db.execute("update prefixes set type='fixed', category='fixed'")
        self.assertEqual([event[0] for event in self.reconcile()], ['up'])

    def test_removed_or_changed_assignment_is_deconfigured(self):
        for prefix in ('', '2001:db8:10:c0::/60', '2001:db8:10:b0::/64'):
            with self.subTest(prefix=prefix):
                self.configure(prefix=prefix)
                self.db.execute('update prefixes set active=1')
                self.db.execute('insert or replace into routes values (?,60,?,0)', (PREFIX, 'fe80::2'))
                self.assertEqual([event[0] for event in self.reconcile()], ['down'])
                self.assertEqual(self.db.execute('select active from prefixes').fetchone(), (0,))
                self.assertEqual(self.db.execute('select count(*) from routes').fetchone(), (0,))

    def test_changed_owner_is_deconfigured(self):
        self.configure(mac='02:00:00:00:00:03')
        self.assertEqual([event[0] for event in self.reconcile()], ['down'])

    def test_changed_class_is_deconfigured(self):
        self.config.hosts['client'].CLASS = 'other'
        self.assertEqual([event[0] for event in self.reconcile()], ['down'])

    def test_expired_fixed_assignment_is_not_reinstalled(self):
        self.db.execute('update prefixes set valid_until=99')
        self.assertEqual([event[0] for event in self.reconcile()], ['down'])

    def test_named_pool_still_uses_pool_validation(self):
        cfg.CLASSES['fixed_lan'].PREFIXES = ['pool']
        with patch.object(cfg, 'PREFIXES', {'pool': SimpleNamespace(LENGTH=60)}):
            self.db.execute("update prefixes set type='pool'")
            self.configure(prefix='')
            self.assertEqual([event[0] for event in self.reconcile()], ['up'])

    def test_match_all_requires_all_configured_identifiers(self):
        with patch.object(cfg, 'IDENTIFICATION', ['mac', 'duid']):
            self.assertEqual([event[0] for event in self.reconcile()], ['down'])

    def test_ambiguous_owner_is_not_reused(self):
        self.config.index_mac[MAC].append(object())
        self.assertIsNone(self.config.find_client_config(SimpleNamespace(mac=MAC)))

    def test_sql_client_config_resolves_fixed_assignment(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.execute('create table hosts (hostname, mac, duid, class, address, prefix, id)')
        db.execute('insert into hosts values (?,?,?,?,?,?,?)',
                   ('client', MAC, '', 'fixed_lan', '', '2001:db8:10:b0::/60', ''))
        config = Store(None, None)
        config.config_prefix_support = True
        config.query = lambda sql: db.execute(sql).fetchall()
        with patch.object(cfg, 'STORE_CONFIG', 'sqlite'), patch.object(route, 'config_store', config):
            route.manage_prefixes_routes()
        self.assertEqual(route_queue.get_nowait()[0], 'up')

    def test_from_config_marks_fixed_prefix_metadata(self):
        from dhcpy6d.client.from_config import from_config
        from dhcpy6d.constants import CONST
        client = SimpleNamespace(prefixes=[], addresses=[], bootfiles=[])
        tx = SimpleNamespace(interface='lan0', ia_options=[CONST.OPTION.IA_PD])
        current_class = cfg.CLASSES['fixed_lan']
        current_class.INTERFACE = ['lan0']
        current_class.ANSWER = 'normal'
        current_class.ADVERTISE = ['prefixes']
        current_class.BOOTFILES = []
        from_config(client, self.config.hosts['client'], tx)
        self.assertEqual([(p.TYPE, p.CATEGORY, p.CLASS) for p in client.prefixes],
                         [('fixed', 'fixed', 'fixed_lan')])
