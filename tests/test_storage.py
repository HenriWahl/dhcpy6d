import os
import sys
import tempfile
import types
import unittest


_TEMP_VOLATILE_DB = tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False)
_TEMP_VOLATILE_DB.close()
_TEMP_CONFIG = tempfile.NamedTemporaryFile('w', suffix='.conf', delete=False)
_TEMP_CONFIG.write('[dhcpy6d]\n')
_TEMP_CONFIG.write('interface = eth0\n')
_TEMP_CONFIG.write('ignore_interface = yes\n')
_TEMP_CONFIG.write('store_config = none\n')
_TEMP_CONFIG.write(f'store_sqlite_volatile = {_TEMP_VOLATILE_DB.name}\n')
_TEMP_CONFIG.flush()
_TEMP_CONFIG.close()

_ORIGINAL_ARGV = list(sys.argv)
sys.argv = [sys.argv[0], '--config', _TEMP_CONFIG.name]

_dns = types.ModuleType('dns')
_dns_resolver = types.ModuleType('dns.resolver')
_dns_tsigkeyring = types.ModuleType('dns.tsigkeyring')


class _DummyResolver:
    def __init__(self):
        self.nameservers = []


class _DummyDnsError(Exception):
    pass


_dns_resolver.Resolver = _DummyResolver
_dns_resolver.NoAnswer = _DummyDnsError
_dns_resolver.NoNameservers = _DummyDnsError
_dns_tsigkeyring.from_text = lambda *_args, **_kwargs: {}
_dns.resolver = _dns_resolver
_dns.tsigkeyring = _dns_tsigkeyring
sys.modules.setdefault('dns', _dns)
sys.modules.setdefault('dns.resolver', _dns_resolver)
sys.modules.setdefault('dns.tsigkeyring', _dns_tsigkeyring)

_ORIGINAL_CHOWN = os.chown
os.chown = lambda *_args, **_kwargs: None

from dhcpy6d.storage.sqlite import SQLite
from dhcpy6d.storage.store import Store

os.chown = _ORIGINAL_CHOWN
sys.argv = _ORIGINAL_ARGV


def tearDownModule():
    try:
        from dhcpy6d.storage import close_stores
        close_stores()
    finally:
        for path in (_TEMP_CONFIG.name, _TEMP_VOLATILE_DB.name):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


class VolatileStoreBatchTest(unittest.TestCase):
    def test_store_batches_address_writes(self):
        store = object.__new__(Store)
        batches = []
        store.table_leases = 'leases'
        store.table_prefixes = 'prefixes'
        store.query = lambda _query: []
        store.query_batch = lambda queries: batches.append(tuple(queries))
        transaction = types.SimpleNamespace(
            client=types.SimpleNamespace(
                addresses=[
                    types.SimpleNamespace(
                        ADDRESS='20010db8000000000000000000000001',
                        PREFERRED_LIFETIME=5400, VALID_LIFETIME=7200,
                        TYPE='fixed', CATEGORY='fixed', IA_TYPE='na',
                    ),
                    types.SimpleNamespace(
                        ADDRESS='20010db8000000000000000000000002',
                        PREFERRED_LIFETIME=5400, VALID_LIFETIME=7200,
                        TYPE='fixed', CATEGORY='fixed', IA_TYPE='na',
                    ),
                ],
                prefixes=[], hostname='paperless', client_class='default_eth0',
            ),
            last_message_received_type=3, mac='02:00:c0:a8:00:02',
            duid='0001000130750a150200c0a80002', iaid='c0a80002',
        )

        Store.store(store, transaction, now=100)

        self.assertEqual(len(batches), 1)
        self.assertEqual(len(batches[0]), 2)
        self.assertTrue(all(query.startswith('INSERT INTO leases') for query in batches[0]))

    def test_sqlite_batch_rolls_back_all_writes_on_integrity_error(self):
        import sqlite3

        store = object.__new__(SQLite)
        store.db_module = sqlite3
        store.connection = sqlite3.connect(':memory:')
        store.cursor = store.connection.cursor()
        store.db_connect = lambda: False
        store.cursor.execute('CREATE TABLE leases (address TEXT PRIMARY KEY)')

        result = store.db_query((
            "INSERT INTO leases VALUES ('20010db8000000000000000000000001')",
            "INSERT INTO leases VALUES ('20010db8000000000000000000000001')",
        ))

        self.assertEqual(result, 'INSERT_ERROR')
        self.assertEqual(store.cursor.execute('SELECT * FROM leases').fetchall(), [])
