"""Neighbour identity must include its link-local scope."""
import unittest
from unittest.mock import patch

from tests.test_prefix_substitution import cfg
import sqlite3
from dhcpy6d import macs
from dhcpy6d.globals import collected_macs
from dhcpy6d.helpers import NeighborCacheRecord, decompress_ip6
from dhcpy6d.storage.store import Store
from dhcpy6d.storage.schemas import MYSQL_SQLITE, legacy_adjustments


class InterfaceMacTest(unittest.TestCase):
    def setUp(self):
        self.saved = collected_macs.copy()
        collected_macs.clear()
        self.db = sqlite3.connect(':memory:')
        self.db.execute(MYSQL_SQLITE['macs_llips'])
        self.store = Store(None, None)
        self.store.query = lambda sql: self.db.execute(sql).fetchall()
        self.llip = decompress_ip6('fe80::2')

    def tearDown(self):
        self.db.close()
        collected_macs.clear()
        collected_macs.update(self.saved)

    def test_collection_and_persistence_keep_both_interfaces(self):
        records = {(nic, self.llip): NeighborCacheRecord(self.llip, mac, nic, 100)
                   for nic, mac in [('lan0', '02:00:00:00:00:11'), ('lan1', '02:00:00:00:00:22')]}
        with patch.object(macs, 'get_neighbor_cache_linux', return_value=records), \
                patch.object(macs, 'volatile_store', self.store), \
                patch.object(macs, 'OS', 'Linux'), patch.object(cfg, 'CACHE_MAC_LLIP', True):
            macs.collect_macs(100)
        self.assertEqual({key: record.mac for key, record in collected_macs.items()},
                         {key: record.mac for key, record in records.items()})
        collected_macs.clear()
        self.store.collect_macs_from_db()
        self.assertEqual({key: record.mac for key, record in collected_macs.items()},
                         {key: record.mac for key, record in records.items()})

    def test_relearned_mac_replaces_only_its_interface(self):
        collected_macs[('lan0', self.llip)] = NeighborCacheRecord(self.llip, '02:00:00:00:00:11', 'lan0', 100)
        collected_macs[('lan1', self.llip)] = NeighborCacheRecord(self.llip, '02:00:00:00:00:22', 'lan1', 100)
        with patch.object(macs, 'volatile_store', self.store), patch.object(cfg, 'CACHE_MAC_LLIP', True):
            macs.remember_neighbor(NeighborCacheRecord(self.llip, '02:00:00:00:00:33', 'lan0', 101))
        self.assertEqual(collected_macs[('lan0', self.llip)].mac, '02:00:00:00:00:33')
        self.assertEqual(collected_macs[('lan1', self.llip)].mac, '02:00:00:00:00:22')

    def test_bsd_command_output_keeps_scopes_and_skips_incomplete_rows(self):
        output = "header\nfe80::2%lan0 02:00:00:00:00:11 lan0\nfe80::2%lan1 02:00:00:00:00:22 lan1\nfe80::3 (incomplete) lan0"
        with patch.object(macs, 'OS', 'BSD'), patch.object(cfg, 'INTERFACE', ['lan0', 'lan1']), \
                patch.object(macs.subprocess, 'getoutput', return_value=output), \
                patch.object(cfg, 'CACHE_MAC_LLIP', False), patch.object(macs, 'volatile_store') as store:
            macs.collect_macs(100)
        self.assertEqual(set(collected_macs), {('lan0', self.llip), ('lan1', self.llip)})
        store.store_mac_llip.assert_not_called()

    def test_mac_replacement_only_updates_its_own_scope(self):
        for interface in ('lan0', 'lan1'):
            self.store.store_mac_llip('02:00:00:00:00:11', self.llip, 100, interface)
        self.store.store_mac_llip('02:00:00:00:00:33', self.llip, 101, 'lan0')
        self.assertEqual(self.db.execute('SELECT interface,mac FROM macs_llips ORDER BY interface').fetchall(),
                         [('lan0', '02:00:00:00:00:33'), ('lan1', '02:00:00:00:00:11')])

    def test_legacy_cache_discarded_without_touching_leases(self):
        self.db.execute('DROP TABLE macs_llips')
        self.db.execute('CREATE TABLE macs_llips(mac text PRIMARY KEY,link_local_ip text,last_update bigint)')
        self.db.execute("INSERT INTO macs_llips VALUES ('02:00:00:00:00:11','fe80::2',100)")
        self.db.execute('CREATE TABLE leases(last_message int,last_update bigint)')
        self.db.execute('INSERT INTO leases VALUES (3,100)')
        self.db.execute('CREATE TABLE meta(item_key text PRIMARY KEY,item_value text)')
        self.db.execute("INSERT INTO meta VALUES ('version','3')")
        self.store.get_db_version = lambda: self.db.execute("SELECT item_value FROM meta WHERE item_key='version'").fetchone()[0]
        self.db.execute('CREATE TABLE prefixes(prefix text)')
        self.db.execute("INSERT INTO prefixes VALUES ('retained-prefix')")
        self.db.execute('CREATE TABLE routes(router text)')
        self.db.execute("INSERT INTO routes VALUES ('retained-router')")
        legacy_adjustments(self.store)
        self.assertEqual(self.store.get_db_version(), '4')
        self.assertEqual(self.db.execute('SELECT * FROM leases').fetchall(), [(3, 100)])
        self.assertEqual(self.db.execute('SELECT * FROM macs_llips').fetchall(), [])
        self.assertEqual(self.db.execute('SELECT * FROM prefixes').fetchall(), [('retained-prefix',)])
        self.assertEqual(self.db.execute('SELECT * FROM routes').fetchall(), [('retained-router',)])
        self.store.store_mac_llip('02:00:00:00:00:22', self.llip, 101, 'lan1')


if __name__ == '__main__':
    unittest.main()
