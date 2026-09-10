import atexit
import os
import sys
import tempfile
import types
import unittest
from unittest import mock


# dhcpy6d parses CLI arguments at import time, so provide a minimal portable config.
_TEMP_VOLATILE_DB = tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False)
_TEMP_VOLATILE_DB.close()
_TEMP_CONFIG = tempfile.NamedTemporaryFile('w', suffix='.conf', delete=False)
_TEMP_CONFIG.write('[dhcpy6d]\n')
_TEMP_CONFIG.write('interface = vlan100 vlan110\n')
_TEMP_CONFIG.write('ignore_interface = yes\n')
_TEMP_CONFIG.write('store_config = none\n')
_TEMP_CONFIG.write(f'store_sqlite_volatile = {_TEMP_VOLATILE_DB.name}\n')
_TEMP_CONFIG.flush()
_TEMP_CONFIG.close()
_ORIGINAL_ARGV = list(sys.argv)
sys.argv = [sys.argv[0], '--config', _TEMP_CONFIG.name]

# Optional runtime dependency in this repo; these tests do not exercise DNS behavior.
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

import dhcpy6d.client as client_module
from dhcpy6d.client import Client
from dhcpy6d.config import Class, cfg
from dhcpy6d.constants import CONST
from dhcpy6d.helpers import decompress_ip6
from dhcpy6d.storage.store import ClientConfig
from dhcpy6d.storage.textfile import Textfile

os.chown = _ORIGINAL_CHOWN
sys.argv = _ORIGINAL_ARGV


def _cleanup_temp_files():
    for path in (_TEMP_CONFIG.name, _TEMP_VOLATILE_DB.name):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


atexit.register(_cleanup_temp_files)


class ClientInterfaceIdentificationTest(unittest.TestCase):
    MAC = '02:00:00:00:00:01'
    HOME_ADDRESS = '2001:db8:110::10'
    ADMIN_ADDRESS = '2001:db8:100::10'

    def setUp(self):
        self._old_classes = cfg.CLASSES
        self._old_filters = cfg.FILTERS
        self._old_identification = cfg.IDENTIFICATION
        self._old_identification_mode = cfg.IDENTIFICATION_MODE
        self._old_store_config = cfg.STORE_CONFIG
        self._old_store_file_config = cfg.STORE_FILE_CONFIG

        home = Class(name='home')
        home.INTERFACE = ['vlan110']
        admin = Class(name='admin')
        admin.INTERFACE = ['vlan100']
        cfg.CLASSES = {'home': home, 'admin': admin}
        cfg.FILTERS = {}
        cfg.IDENTIFICATION = ['mac']
        cfg.IDENTIFICATION_MODE = 'match_all'
        cfg.STORE_CONFIG = 'file'

        self._clients_file = tempfile.NamedTemporaryFile('w', suffix='.conf', delete=False)
        self._clients_file.write(
            '[laptop-home]\n'
            'hostname = laptop-home\n'
            f'mac = {self.MAC}\n'
            f'address = {self.HOME_ADDRESS}\n'
            'class = home\n\n'
            '[laptop-admin]\n'
            'hostname = laptop-admin\n'
            f'mac = {self.MAC}\n'
            f'address = {self.ADMIN_ADDRESS}\n'
            'class = admin\n'
        )
        self._clients_file.flush()
        self._clients_file.close()
        cfg.STORE_FILE_CONFIG = self._clients_file.name
        self.config_store = Textfile(None, None)

    def tearDown(self):
        cfg.CLASSES = self._old_classes
        cfg.FILTERS = self._old_filters
        cfg.IDENTIFICATION = self._old_identification
        cfg.IDENTIFICATION_MODE = self._old_identification_mode
        cfg.STORE_CONFIG = self._old_store_config
        cfg.STORE_FILE_CONFIG = self._old_store_file_config
        os.unlink(self._clients_file.name)

    def transaction(self, interface, message_type):
        return types.SimpleNamespace(
            interface=interface,
            mac=self.MAC,
            duid='0001000100000000020000000001',
            hostname='laptop',
            last_message_received_type=message_type,
            addresses=[],
            prefixes=[],
            ia_options=[CONST.OPTION.IA_NA],
            answer='normal',
            client_architecture='',
            known_client_architecture='',
            user_class='',
        )

    def test_same_mac_selects_fixed_configuration_for_receiving_interface(self):
        cases = (
            ('vlan110', 'home', 'laptop-home', self.HOME_ADDRESS),
            ('vlan100', 'admin', 'laptop-admin', self.ADMIN_ADDRESS),
        )

        for message_type in (CONST.MESSAGE.SOLICIT, CONST.MESSAGE.REQUEST):
            for interface, expected_class, expected_hostname, expected_address in cases:
                with self.subTest(message_type=message_type, interface=interface):
                    transaction = self.transaction(interface, message_type)
                    with mock.patch.object(client_module, 'config_store', self.config_store):
                        client = Client(transaction)

                    self.assertEqual(client.client_class, expected_class)
                    self.assertEqual(client.hostname, expected_hostname)
                    self.assertEqual(len(client.addresses), 1)
                    self.assertEqual(
                        client.addresses[0].ADDRESS,
                        decompress_ip6(expected_address),
                    )

    def test_renew_and_rebind_receive_interface_scoped_configuration(self):
        expected_by_interface = {
            'vlan110': self.config_store.hosts['laptop-home'],
            'vlan100': self.config_store.hosts['laptop-admin'],
        }

        for message_type in (CONST.MESSAGE.RENEW, CONST.MESSAGE.REBIND):
            for interface, expected_config in expected_by_interface.items():
                with self.subTest(message_type=message_type, interface=interface):
                    transaction = self.transaction(interface, message_type)
                    transaction.addresses = [expected_config.ADDRESS[0]]
                    with mock.patch.object(client_module, 'config_store', self.config_store), \
                            mock.patch.object(client_module, 'reuse_lease') as reuse_lease:
                        Client(transaction)

                    self.assertIs(reuse_lease.call_args.kwargs['client_config'], expected_config)

    def test_multiple_matches_on_same_interface_remain_ambiguous(self):
        duplicate = ClientConfig(
            hostname='laptop-home-duplicate',
            client_class='home',
            mac=self.MAC,
            address='2001:db8:110::11',
        )
        self.config_store.index_mac[self.MAC].append(duplicate)
        transaction = self.transaction('vlan110', CONST.MESSAGE.SOLICIT)

        with mock.patch.object(client_module, 'config_store', self.config_store), \
                mock.patch.object(client_module, 'default') as default:
            client = Client(transaction)

        default.assert_called_once_with(
            client=client,
            client_config=None,
            transaction=transaction,
        )


if __name__ == '__main__':
    unittest.main()
