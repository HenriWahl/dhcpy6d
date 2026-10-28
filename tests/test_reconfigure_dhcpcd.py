"""Optional compatibility test using dhcpcd's actual auth.c implementation.

See doc/reconfigure.rst for building DHCPCD_AUTH_CHECK from dhcpcd 9.4.1.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from dhcpy6d.reconfigure import ReconfigureService
from tests.test_reconfigure import reply


@unittest.skipUnless(os.environ.get('DHCPCD_AUTH_CHECK'), 'dhcpcd C authentication checker not configured')
class TestDhcpcdAuthentication(unittest.TestCase):
    def test_real_client_accepts_packets_and_rejects_replay_and_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            sock = Mock()
            transaction = SimpleNamespace(duid='00010001', interface='lan0',
                client_llip='fe800000000000000000000000000002', options={20: ''},
                last_message_received_type=3)
            manager = ReconfigureService(str(path / 'state'), 'aabb', sock, ['lan0'], Mock())
            try:
                (path / 'reply1').write_bytes(reply() + manager.reply_options(transaction, reply()))
                with patch('socket.if_nametoindex', return_value=7):
                    manager.trigger()
                    manager.poll()
                    (path / 'reconf1').write_bytes(sock.sendto.call_args.args[0])
                    manager.close()
                    manager = ReconfigureService(str(path / 'state'), 'aabb', sock, ['lan0'], Mock())
                    manager.trigger()
                    manager.poll()
                    packet = sock.sendto.call_args.args[0]
                    (path / 'reconf2').write_bytes(packet)
                    (path / 'tampered').write_bytes(packet[:-1] + bytes([packet[-1] ^ 1]))
                    (path / 'reply2').write_bytes(reply() + manager.reply_options(transaction, reply()))
                result = subprocess.run([os.environ['DHCPCD_AUTH_CHECK'],
                    '+' + str(path / 'reply1'), '+' + str(path / 'reconf1'),
                    '-' + str(path / 'reconf1'), '-' + str(path / 'tampered'),
                    '+' + str(path / 'reconf2'), '+' + str(path / 'reply2')],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            finally:
                manager.close()
