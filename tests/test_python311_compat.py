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
from dhcpy6d.config import Address
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
