import atexit
import importlib
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace


# dhcpy6d parses CLI args at import time, so provide a minimal portable config first.
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

# Optional runtime dependency in this repo; tests here don't exercise DNS behavior.
import types

_dns = types.ModuleType('dns')
_dns_query = types.ModuleType('dns.query')
_dns_reversename = types.ModuleType('dns.reversename')
_dns_resolver = types.ModuleType('dns.resolver')
_dns_update = types.ModuleType('dns.update')
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
_dns.query = _dns_query
_dns.reversename = _dns_reversename
_dns.resolver = _dns_resolver
_dns.update = _dns_update
_dns.tsigkeyring = _dns_tsigkeyring
sys.modules.setdefault('dns', _dns)
sys.modules.setdefault('dns.query', _dns_query)
sys.modules.setdefault('dns.reversename', _dns_reversename)
sys.modules.setdefault('dns.resolver', _dns_resolver)
sys.modules.setdefault('dns.update', _dns_update)
sys.modules.setdefault('dns.tsigkeyring', _dns_tsigkeyring)

_ORIGINAL_CHOWN = os.chown
os.chown = lambda *_args, **_kwargs: None

from dhcpy6d.client import Client
from dhcpy6d.client.from_config import from_config
from dhcpy6d.config import cfg
from dhcpy6d.helpers import (inject_dynamic_prefix,
                             normalize_route_prefix)
from dhcpy6d.route import manage_prefixes_routes
from dhcpy6d.storage.store import ClientConfig
from dhcpy6d.threads import RouteThread
from dhcpy6d.globals import route_queue, timer
from dhcpy6d import route as route_module
reuse_lease_module = importlib.import_module('dhcpy6d.client.reuse_lease')
from_config_module = importlib.import_module('dhcpy6d.client.from_config')

os.chown = _ORIGINAL_CHOWN
sys.argv = _ORIGINAL_ARGV


def _cleanup_temp_config():
    for path in (_TEMP_CONFIG.name, _TEMP_VOLATILE_DB.name):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


atexit.register(_cleanup_temp_config)


class MockTransaction:
    def __init__(self):
        self.ia_options = [3, 25]  # IA_NA and IA_PD
        self.interface = 'eth0'
        self.hostname = 'testclient'
        self.duid = '00010001'
        self.answer = 'normal'


class MockClass:
    def __init__(self):
        self.INTERFACE = ['eth0']
        self.ANSWER = 'normal'
        self.ADDRESSES = []
        self.BOOTFILES = []
        self.PREFIXES = []
        self.ADVERTISE = []


class MockPrefixTransaction:
    def __init__(self):
        self.ia_options = [25]  # IA_PD
        self.interface = 'eth0'
        self.hostname = 'iserv'
        self.duid = '00010001294b6c4f52540045fef0'
        self.mac = '02:00:c0:a8:ff:31'
        self.answer = 'normal'
        self.prefixes = ['2001:0db8:0838:8f00:0000:0000:0000:0000/63']
        self.addresses = []


class MockAddressTransaction:
    def __init__(self):
        self.ia_options = [3]  # IA_NA
        self.interface = 'eth0'
        self.hostname = 'iserv'
        self.duid = '00010001294b6c4f52540045fef0'
        self.mac = '02:00:c0:a8:ff:31'
        self.answer = 'normal'
        self.addresses = ['2001:0db8:0838:8fa3:0000:0000:0000:0002']
        self.prefixes = []


class PrefixSubstitutionTest(unittest.TestCase):
    def setUp(self):
        self._old_prefix = cfg.PREFIX
        self._old_classes = cfg.CLASSES
        cfg.PREFIX = '2001:db8'
        cfg.CLASSES = {'default': MockClass()}

    def tearDown(self):
        cfg.PREFIX = self._old_prefix
        cfg.CLASSES = self._old_classes

    def test_prefix_substitution_is_normalized_consistently(self):
        cc = ClientConfig(
            hostname='testclient',
            client_class='default',
            address='$prefix$::1',
            prefix='$prefix$::/64',
        )

        # ClientConfig should already be normalized consistently.
        self.assertEqual(cc.ADDRESS, ['20010db8000000000000000000000001'])
        self.assertEqual(
            cc.PREFIX,
            [{'address': '20010db8000000000000000000000000', 'length': '64'}],
        )

        client = Client()
        transaction = MockTransaction()
        from_config(client=client, client_config=cc, transaction=transaction)

        self.assertEqual(client.addresses[0].ADDRESS, '20010db8000000000000000000000001')
        self.assertEqual(client.prefixes[0].PREFIX, '20010db8000000000000000000000000')
        self.assertEqual(client.prefixes[0].LENGTH, '64')

    def test_from_config_uses_fixed_client_addresses_without_class_extras(self):
        fixed_address = '20010db808388f000000c0fffea80002'
        random_address = '20010db808388f000123456789abcdef'
        original_addresses = cfg.ADDRESSES
        original_parse_pattern_address = from_config_module.parse_pattern_address
        cfg.CLASSES['default'].ADDRESSES = ['class_eui64', 'class_random']
        cfg.ADDRESSES = {
            'class_eui64': SimpleNamespace(
                CATEGORY='eui64', IA_TYPE='na', PREFERRED_LIFETIME=5400,
                VALID_LIFETIME=7200, CLASS='default', TYPE='class_eui64',
                DNS_UPDATE=False, DNS_ZONE='', DNS_REV_ZONE='', DNS_TTL=0,
            ),
            'class_random': SimpleNamespace(
                CATEGORY='random', IA_TYPE='ta', PREFERRED_LIFETIME=5400,
                VALID_LIFETIME=7200, CLASS='default', TYPE='class_random',
                DNS_UPDATE=False, DNS_ZONE='', DNS_REV_ZONE='', DNS_TTL=0,
            ),
        }
        from_config_module.parse_pattern_address = lambda address, *_args: (
            fixed_address if address.TYPE == 'class_eui64' else random_address
        )
        try:
            client = Client()
            transaction = MockTransaction()
            client_config = ClientConfig(
                hostname='paperless', client_class='default', address=fixed_address,
            )
            from_config(client=client, client_config=client_config, transaction=transaction)
            self.assertEqual(
                [(address.ADDRESS, address.IA_TYPE) for address in client.addresses],
                [(fixed_address, 'na')],
            )
        finally:
            cfg.ADDRESSES = original_addresses
            from_config_module.parse_pattern_address = original_parse_pattern_address

    def test_prefix_substitution_keeps_legacy_concat_when_it_fits(self):
        cfg.PREFIX = '2001:db8:10:20'

        cc = ClientConfig(
            hostname='iserv',
            client_class='default',
            address='$prefix$a3::2',
            prefix='$prefix$::/63',
        )

        self.assertEqual(cc.ADDRESS, ['20010db8001020a30000000000000002'])
        self.assertEqual(
            cc.PREFIX,
            [{'address': '20010db8001000200000000000000000', 'length': '63'}],
        )

    def test_inject_dynamic_prefix_reports_collision(self):
        value, collision = inject_dynamic_prefix('$prefix$19::2', '2001:db8:8317')
        self.assertEqual(value, '2001:db8:8317:19::2')
        self.assertTrue(collision)

    def test_inject_dynamic_prefix_uses_concat_when_hextet_can_be_completed(self):
        value, collision = inject_dynamic_prefix('$prefix$00::/63', '2001:db8:838:8f', allow_legacy_concat=True)
        self.assertEqual(value, '2001:db8:838:8f00::/63')
        self.assertFalse(collision)

    def test_client_config_prefix_concat_keeps_8f00_shape(self):
        cfg.PREFIX = '2001:db8:838:8f'
        cc = ClientConfig(
            hostname='iserv',
            client_class='default',
            address='$prefix$a3::2',
            prefix='$prefix$00::/63',
        )
        self.assertEqual(cc.ADDRESS, ['20010db808388fa30000000000000002'])
        self.assertEqual(
            cc.PREFIX,
            [{'address': '20010db808388f000000000000000000', 'length': '63'}],
        )

    def test_integration_prefix_concat_stays_8f00_until_route_call(self):
        cfg.PREFIX = '2001:db8:838:8f'
        cc = ClientConfig(
            hostname='iserv',
            client_class='default',
            address='$prefix$a3::2',
            prefix='$prefix$00::/63',
        )
        client = Client()
        transaction = MockTransaction()
        transaction.mac = '02:00:c0:a8:ff:31'
        transaction.duid = '00010001294b6c4f52540045fef0'
        from_config(client=client, client_config=cc, transaction=transaction)

        self.assertEqual(client.prefixes[0].PREFIX, '20010db808388f000000000000000000')
        self.assertEqual(client.prefixes[0].LENGTH, '63')

        call = RouteThread.build_route_call(
            'up',
            '/usr/sbin/dhcpy6d-add-route $prefix$/$length$ $router$ dmz_office',
            client.prefixes[0].PREFIX,
            client.prefixes[0].LENGTH,
            'fe800000000000000000000000000002',
        )
        self.assertIn('2001:0db8:0838:8f00:0000:0000:0000:0000/63', call)

    def test_inject_dynamic_prefix_prefers_legacy_double_colon_shape(self):
        value, collision = inject_dynamic_prefix('$prefix$dead:beef', '2001:db8:10')
        self.assertEqual(value, '2001:db8:10::dead:beef')
        self.assertTrue(collision)

    def test_route_prefix_normalization_accepts_legacy_replay_value(self):
        self.assertEqual(
            normalize_route_prefix('2001:db8:10:21', '63'),
            '2001:0db8:0010:0020:0000:0000:0000:0000',
        )

    def test_route_thread_build_route_call_normalizes_prefix_argument(self):
        call = RouteThread.build_route_call(
            'up',
            '/usr/sbin/dhcpy6d-add-route $prefix$/$length$ $router$ dmz',
            '20010db8001000210000000000000000',
            '63',
            'fe800000000000000000000000000002',
        )

        self.assertEqual(
            call,
            '/usr/sbin/dhcpy6d-add-route '
            '2001:0db8:0010:0020:0000:0000:0000:0000/63 '
            'fe80:0000:0000:0000:0000:0000:0000:0002 dmz',
        )

    def test_manage_prefixes_routes_deconfigures_stale_active_route(self):
        class _MockStore:
            def __init__(self):
                self.deactivated = []
                self.removed = []

            def release_free_prefixes(self, _now):
                return None

            def get_inactive_prefixes(self):
                return []

            def get_active_prefixes(self):
                return ['20010db808388f000000000000000000']

            def get_route(self, _prefix):
                return '63', 'fe800000000000000000000000000002', 'default'

            def get_prefix_record(self, _prefix):
                # stale: configured class does not contain this prefix type anymore
                return ('20010db808388f000000000000000000', '63', 'obsolete', 'default', 1)

            def deactivate_prefix(self, prefix):
                self.deactivated.append(prefix)

            def remove_route(self, prefix):
                self.removed.append(prefix)

        original_store = route_module.volatile_store
        mock_store = _MockStore()
        route_module.volatile_store = mock_store
        timer.time = 0
        cfg.CLASSES['default'].CALL_DOWN = '/usr/sbin/dhcpy6d-del-route $prefix$/$length$ $router$'
        while not route_queue.empty():
            route_queue.get_nowait()
        try:
            manage_prefixes_routes()
            self.assertEqual(
                mock_store.deactivated,
                ['20010db808388f000000000000000000'],
            )
            self.assertEqual(
                mock_store.removed,
                ['20010db808388f000000000000000000'],
            )
            self.assertFalse(route_queue.empty())
            mode, _call, prefix, _length, _router = route_queue.get_nowait()
            self.assertEqual(mode, 'down')
            self.assertEqual(prefix, '20010db808388f000000000000000000')
        finally:
            route_module.volatile_store = original_store

    def test_reuse_lease_refuses_unconfigured_prefix_with_zero_lifetimes(self):
        class _MockLeaseStore:
            @staticmethod
            def check_prefix(_prefix, _length, _transaction):
                return [('iserv', '20010db808388f000000000000000000', '63', 'obsolete', 'range', 'default', 0)]

        original_store = reuse_lease_module.volatile_store
        reuse_lease_module.volatile_store = _MockLeaseStore()
        cfg.CLASSES['default'].ADVERTISE = ['prefixes']
        cfg.CLASSES['default'].PREFIXES = []
        cfg.CLASSES['default_eth0'] = cfg.CLASSES['default']
        try:
            client = Client()
            transaction = MockPrefixTransaction()
            reuse_lease_module.reuse_lease(client=client, client_config=None, transaction=transaction)
            self.assertEqual(len(client.prefixes), 1)
            self.assertEqual(client.prefixes[0].PREFIX.replace(':', ''), '20010db808388f000000000000000000')
            self.assertEqual(client.prefixes[0].LENGTH, '63')
            self.assertEqual(client.prefixes[0].PREFERRED_LIFETIME, 0)
            self.assertEqual(client.prefixes[0].VALID_LIFETIME, 0)
        finally:
            reuse_lease_module.volatile_store = original_store

    def test_reuse_lease_refuses_unconfigured_address_with_zero_lifetimes(self):
        class _MockLeaseStore:
            def __init__(self):
                self.deactivated = []

            @staticmethod
            def check_lease(_address, _transaction):
                return [('iserv', '20010db808388fa30000000000000002', 'obsolete', 'range', 'na', 'default', 0)]

            def deactivate_lease(self, address):
                self.deactivated.append(address)

        mock_store = _MockLeaseStore()
        original_store = reuse_lease_module.volatile_store
        reuse_lease_module.volatile_store = mock_store
        cfg.CLASSES['default'].ADVERTISE = ['addresses']
        cfg.CLASSES['default'].ADDRESSES = []
        cfg.CLASSES['default_eth0'] = cfg.CLASSES['default']
        try:
            client = Client()
            transaction = MockAddressTransaction()
            reuse_lease_module.reuse_lease(client=client, client_config=None, transaction=transaction)
            self.assertEqual(len(client.addresses), 1)
            self.assertEqual(client.addresses[0].ADDRESS.replace(':', ''), '20010db808388fa30000000000000002')
            self.assertEqual(client.addresses[0].PREFERRED_LIFETIME, 0)
            self.assertEqual(client.addresses[0].VALID_LIFETIME, 0)
            self.assertEqual(mock_store.deactivated, ['20010db808388fa30000000000000002'])
        finally:
            reuse_lease_module.volatile_store = original_store


if __name__ == "__main__":
    unittest.main()
