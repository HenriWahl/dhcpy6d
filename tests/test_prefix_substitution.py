import atexit
import os
import sys
import tempfile
import unittest


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
from dhcpy6d.storage.store import ClientConfig
from dhcpy6d.threads import RouteThread

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
        value, collision = inject_dynamic_prefix('$prefix$00::/63', '2001:db8:838:8f')
        self.assertEqual(value, '2001:db8:838:8f00::/63')
        self.assertFalse(collision)

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


if __name__ == "__main__":
    unittest.main()
