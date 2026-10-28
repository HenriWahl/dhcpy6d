"""Exercise final Reply integration using the existing portable config fixture."""
import binascii
import importlib.util
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tests.test_prefix_substitution import cfg
from dhcpy6d import handler, reconfigure
from tests.test_reconfigure import option, options, reply


class TestReconfigureHandler(unittest.TestCase):
    def test_final_reply_contains_key_and_dry_run_does_not_enroll(self):
        with tempfile.TemporaryDirectory() as directory:
            sock = Mock()
            manager = reconfigure.ReconfigureService(directory + '/state', 'aabb', sock, ['lan0'], Mock())
            request = object.__new__(handler.RequestHandler)
            request.socket = sock
            request.client_address = ('fe80::2', 546, 0, 7)
            client = SimpleNamespace(addresses=[object()], prefixes=[], get_options_string=lambda: '')
            transaction = SimpleNamespace(answer='normal', duid='00010001', id='010203',
                interface='lan0', client_llip='fe800000000000000000000000000002',
                options={20: ''}, last_message_received_type=3, client=client)
            ia = Mock()
            ia.build.return_value = (reply()[4:].hex(), 3)
            try:
                with patch.object(reconfigure, 'service', manager), \
                     patch.object(handler, 'OPTIONS', {3: ia}), \
                     patch.object(handler, 'config_store', SimpleNamespace(connected=True)), \
                     patch.object(handler, 'volatile_store', SimpleNamespace(connected=True)), \
                     patch.object(cfg, 'SERVERDUID', 'aabb'), \
                     patch.object(cfg, 'REALLY_DO_IT', False):
                    request.build_response(7, transaction, [3])
                    request.finish()
                    manager.trigger()
                    self.assertFalse(manager.pending)
                    sock.sendto.assert_not_called()
                    with patch.object(cfg, 'REALLY_DO_IT', True):
                        request.build_response(7, transaction, [3])
                        request.finish()
                    packet = sock.sendto.call_args.args[0]
                    self.assertEqual(dict(options(packet[4:]))[11][11], 1)
                    self.assertEqual([code for code, _ in options(packet[4:])].count(20), 1)
                    manager.trigger()
                    self.assertTrue(manager.pending)
            finally:
                manager.close()

    def test_prefix_control_triggers_only_after_configuration_update(self):
        service = Mock()
        address = Mock()
        with patch.object(reconfigure, 'service', service), \
             patch.object(cfg, 'ADDRESSES', {'dynamic': address}), \
             patch.object(cfg, 'PREFIXES', {}), \
             patch.object(cfg, 'PREFIX', ''), \
             patch.object(handler, 'volatile_store', Mock()):
            handler.RequestHandler.control_message(binascii.hexlify(b'prefix 20010db8'))
            address.inject_dynamic_prefix_into_prototype.assert_called_once_with('20010db8')
            service.trigger.assert_called_once()


class TestReconfigureStartup(unittest.TestCase):
    def test_startup_triggers_after_privilege_drop_and_skips_missing_prefix(self):
        # Load the real entry point while isolating every OS/network side effect.
        with patch.dict('sys.modules', {'distro': SimpleNamespace(id=lambda: 'test')}):
            spec = importlib.util.spec_from_file_location('reconfigure_main_test', next(parent / 'main.py' for parent in Path(__file__).resolve().parents if (parent / 'main.py').is_file()))
            main = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(main)
        for prefix, enabled, expected in [('20010db8', True, True), ('', True, False), ('20010db8', False, False)]:
            with self.subTest(prefix=prefix, enabled=enabled), ExitStack() as stack:
                manager = Mock()
                server = Mock()
                server.serve_forever.side_effect = KeyboardInterrupt
                stack.enter_context(patch.object(main, 'UDPMulticastIPv6', return_value=server))
                for name in ('QueryQueue', 'TimerThread', 'RouteThread', 'TidyUpThread', 'DNSQueryThread', 'manage_prefixes_routes'):
                    stack.enter_context(patch.object(main, name, Mock()))
                stack.enter_context(patch.object(main, 'config_store', Mock()))
                store = Mock()
                store.get_dynamic_prefix.return_value = None
                stack.enter_context(patch.object(main, 'volatile_store', store))
                dropped = []
                stack.enter_context(patch.object(main.os, 'setgid', lambda value: dropped.append('gid')))
                stack.enter_context(patch.object(main.os, 'setuid', lambda value: dropped.append('uid')))
                stack.enter_context(patch.object(main.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=123)))
                stack.enter_context(patch.object(main.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=123)))
                for name, value in {'PREFIX': prefix, 'ADDRESSES': {'dynamic': SimpleNamespace(PATTERN='$prefix$::1', inject_dynamic_prefix_into_prototype=Mock())},
                                    'PREFIXES': {}, 'RECONFIGURE_STATE_FILE': '/unused', 'REALLY_DO_IT': enabled}.items():
                    stack.enter_context(patch.object(cfg, name, value))
                stack.enter_context(patch.object(reconfigure, 'service', None))
                def create(*args):
                    self.assertEqual(dropped, ['gid', 'uid'])
                    return manager
                factory = stack.enter_context(patch.object(reconfigure, 'ReconfigureService', side_effect=create))
                with self.assertRaises(SystemExit):
                    main.run()
                self.assertEqual(factory.called, enabled)
                self.assertEqual(manager.trigger.called, expected)
                self.assertEqual(manager.start.called, enabled)
                self.assertEqual(manager.close.called, enabled)
