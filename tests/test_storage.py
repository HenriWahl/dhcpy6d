import os
import queue
import sys
import tempfile
import time
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
from dhcpy6d.storage import QueryQueue

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
    @staticmethod
    def transaction():
        return types.SimpleNamespace(
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

    def test_store_batches_address_writes(self):
        store = object.__new__(Store)
        batches = []
        store.table_leases = 'leases'
        store.table_prefixes = 'prefixes'
        store.query = lambda _query: []
        store.query_batch = lambda queries: batches.append(tuple(queries))
        Store.store(store, self.transaction(), now=100)

        self.assertEqual(len(batches), 1)
        self.assertEqual(len(batches[0]), 2)
        self.assertTrue(all(query.startswith('INSERT INTO leases') for query in batches[0]))

    def test_store_queues_write_batch_without_waiting(self):
        store = object.__new__(Store)
        batches = []
        store.table_leases = 'leases'
        store.table_prefixes = 'prefixes'
        store.query = lambda _query: []
        store.query_batch = lambda _queries: self.fail('synchronous write used')
        store.query_batch_async = lambda queries, callback=None: batches.append(tuple(queries))

        Store.store(store, self.transaction(), now=100, wait_for_writes=False)

        self.assertEqual(len(batches), 1)
        self.assertEqual(len(batches[0]), 2)

    def test_async_advertised_lease_is_reserved_before_sqlite_commit(self):
        store = object.__new__(Store)
        store.table_leases = 'leases'
        store.table_prefixes = 'prefixes'
        store.query = lambda _query: []
        store.query_batch_async = lambda _queries, callback=None: None
        transaction = self.transaction()
        transaction.last_message_received_type = 1
        transaction.client.addresses[0].CATEGORY = 'random'
        transaction.client.addresses[0].TYPE = 'dynamic'

        Store.store(store, transaction, now=100, wait_for_writes=False)

        self.assertEqual(
            Store.check_advertised_lease(store, transaction, category='random', atype='dynamic'),
            '20010db8000000000000000000000001',
        )

    def test_async_query_does_not_create_an_answer(self):
        query_queue = queue.Queue()
        answer_queue = queue.Queue()
        store = object.__new__(Store)
        store.query_queue = query_queue
        store.answer_queue = answer_queue
        calls = []
        worker_store = types.SimpleNamespace(
            db_query=lambda query: calls.append(query) or [],
        )
        worker = QueryQueue(store_type=worker_store,
                            query_queue=query_queue,
                            answer_queue=answer_queue)
        worker.start()

        store.query_async('UPDATE leases SET active = 1')

        deadline = time.monotonic() + 1
        while not calls and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(calls, ['UPDATE leases SET active = 1'])
        self.assertTrue(answer_queue.empty())

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
