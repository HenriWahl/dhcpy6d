import os
import sys
import tempfile
import types
import unittest
from unittest import mock


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

import dhcpy6d
from dhcpy6d.client import parse_pattern
from dhcpy6d.config import Address, cfg
from dhcpy6d import handler as handler_module
from dhcpy6d.options import OPTIONS
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


class ConfigurationDefaultsTest(unittest.TestCase):
    def test_default_cleaning_interval_is_accepted_and_converted_to_int(self):
        self.assertEqual(cfg.CLEANING_INTERVAL, 10)
        self.assertIsInstance(cfg.CLEANING_INTERVAL, int)


class LazyExportTest(unittest.TestCase):
    def test_lazy_export_cache_does_not_call_shadowed_globals_name(self):
        fake_module = types.ModuleType('dhcpy6d._compat_fake')
        fake_module.value = object()
        sys.modules[fake_module.__name__] = fake_module

        original_exports = dict(dhcpy6d._LAZY_EXPORTS)
        original_globals_attr = getattr(dhcpy6d, 'globals', None)
        had_globals_attr = hasattr(dhcpy6d, 'globals')
        try:
            dhcpy6d._LAZY_EXPORTS['compat_value'] = ('._compat_fake', 'value')
            dhcpy6d.globals = types.ModuleType('dhcpy6d.globals')

            self.assertIs(dhcpy6d.__getattr__('compat_value'), fake_module.value)
            self.assertIs(dhcpy6d.compat_value, fake_module.value)
        finally:
            dhcpy6d._LAZY_EXPORTS.clear()
            dhcpy6d._LAZY_EXPORTS.update(original_exports)
            sys.modules.pop(fake_module.__name__, None)
            if hasattr(dhcpy6d, 'compat_value'):
                delattr(dhcpy6d, 'compat_value')
            if had_globals_attr:
                dhcpy6d.globals = original_globals_attr
            elif hasattr(dhcpy6d, 'globals'):
                delattr(dhcpy6d, 'globals')


class OptionImportTest(unittest.TestCase):
    def test_mac_dependent_options_load_without_package_lazy_export(self):
        for option_number in (3, 4, 25):
            self.assertIn(option_number, OPTIONS)


class RouteRenewalTest(unittest.TestCase):
    def test_renew_and_rebind_restore_delegated_prefix_routes(self):
        class Transaction:
            def __init__(self, transaction_id, client_llip, interface, message_type, options):
                self.id = transaction_id
                self.client_llip = client_llip
                self.interface = interface
                self.last_message_received_type = message_type
                self.duid = '00010001'
                self.ia_options = [25]
                self.options_request = []
                self.rapid_commit = False
                self.client = None
                self.counter = 1

            @staticmethod
            def get_options_string():
                return ''

        class Client:
            def __init__(self, transaction):
                transaction.client = types.SimpleNamespace(
                    client_class='fixed_eth0', prefixes=[])

        original = {name: getattr(cfg, name) for name in
                    ('IGNORE_MAC', 'IGNORE_UNKNOWN_CLIENTS', 'REQUEST_LIMIT',
                     'INTERFACE', 'DNS_UPDATE')}
        transactions = handler_module.transactions.copy()
        handler_module.transactions.clear()
        try:
            cfg.IGNORE_MAC = True
            cfg.IGNORE_UNKNOWN_CLIENTS = False
            cfg.REQUEST_LIMIT = 0
            cfg.INTERFACE = ['eth0']
            cfg.DNS_UPDATE = False
            for message_type in (handler_module.CONST.MESSAGE.RENEW,
                                 handler_module.CONST.MESSAGE.REBIND):
                handler = object.__new__(handler_module.RequestHandler)
                handler.client_address = ('fe80::1', 547, 0, 1)
                handler.request = (bytes.fromhex(
                    f'{message_type:02x}0000010001000400010001'), None)
                handler.build_response = mock.Mock()
                with mock.patch.object(handler_module.socket, 'if_indextoname', return_value='eth0'), \
                     mock.patch.object(handler_module, 'Transaction', Transaction), \
                     mock.patch.object(handler_module, 'Client', Client), \
                     mock.patch.object(handler_module.volatile_store, 'store'), \
                     mock.patch.object(handler_module, 'modify_route') as modify_route:
                    handler.handle()
                modify_route.assert_called_once_with(mock.ANY, 'up')
        finally:
            handler_module.transactions.clear()
            handler_module.transactions.update(transactions)
            for name, value in original.items():
                setattr(cfg, name, value)


class RandomAddressPatternTest(unittest.TestCase):
    def test_random64_uses_full_16_hex_digits_on_python3(self):
        address = Address(category='random', pattern='2001:db8::$random64$')
        transaction = types.SimpleNamespace(duid='duid', mac='00:11:22:33:44:55')
        volatile_store = types.SimpleNamespace(
            check_advertised_lease=lambda *_args, **_kwargs: None,
        )

        with mock.patch.object(parse_pattern, 'volatile_store', volatile_store):
            with mock.patch.object(parse_pattern.random, 'getrandbits', return_value=0x123456789abcdef0):
                parsed = parse_pattern.parse_pattern_address(address, None, transaction)

        self.assertEqual(parsed, '20010db800000000123456789abcdef0')


class StoreCloseTest(unittest.TestCase):
    def test_close_closes_cursor_and_connection(self):
        store = Store(None, None)
        store.connected = True
        store.cursor = mock.Mock()
        store.connection = mock.Mock()

        store.close()

        store.cursor.close.assert_called_once_with()
        store.connection.close.assert_called_once_with()
        self.assertFalse(store.connected)
