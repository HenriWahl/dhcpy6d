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

from dhcpy6d.client import Client
from dhcpy6d.client.from_config import from_config
from dhcpy6d.config import cfg
from dhcpy6d.storage.store import ClientConfig

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


if __name__ == "__main__":
    unittest.main()
