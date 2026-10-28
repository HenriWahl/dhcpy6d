import hashlib
import hmac
import os
import socket
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from dhcpy6d.reconfigure import ReconfigureService, options


def option(code, value):
    return struct.pack('!HH', code, len(value)) + value


def reply(valid=3600, status=0):
    address = bytes.fromhex('20010db8000000000000000000000001')
    ia = struct.pack('!III', 1, 900, 1800) + option(5, address + struct.pack('!II', valid, valid))
    return b'\x07\x01\x02\x03' + option(3, ia) + option(13, struct.pack('!H', status))


class TestReconfigure(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = self.directory.name + '/state.sqlite'
        self.now = 1000
        self.sock = Mock()
        self.service = self.create_service()
        self.transaction = SimpleNamespace(duid='000100010102030405060708', interface='lan0',
            client_llip='fe800000000000000000000000000002', options={20: ''},
            last_message_received_type=3)

    def tearDown(self):
        self.service.close()
        self.directory.cleanup()

    def create_service(self, server='000100010a0b0c0d'):
        return ReconfigureService(self.path, server, self.sock, ['lan0'], Mock(), clock=lambda: self.now)

    def enroll(self):
        return self.service.reply_options(self.transaction, reply())

    def test_key_delivery_only_for_successful_opted_in_initial_reply(self):
        for packet in (b'\x02\x01\x02\x03', reply(status=2), reply(valid=0)):
            self.assertEqual(self.service.reply_options(self.transaction, packet), b'')
        self.transaction.options = {}
        self.assertEqual(self.enroll(), b'')
        self.service.trigger()
        self.service.poll()
        self.sock.sendto.assert_not_called()
        self.transaction.options = {20: ''}
        opts = dict(options(self.enroll()))
        self.assertEqual(opts[20], b'')
        self.assertEqual(opts[11][:3], b'\x03\x01\x00')
        self.assertEqual(opts[11][11], 1)
        self.assertEqual(len(opts[11]), 28)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    @patch('socket.if_nametoindex', return_value=7)
    def test_authenticated_packet_and_persisted_replay(self, _index):
        key = dict(options(self.enroll()))[11][12:]
        self.service.trigger()
        self.service.poll()
        packet, destination = self.sock.sendto.call_args.args
        self.assertEqual(destination, ('fe80::2', 546, 0, 7))
        self.assertEqual(packet[:4], b'\x0a\x00\x00\x00')
        opts = dict(options(packet[4:]))
        self.assertEqual(opts[1].hex(), self.transaction.duid)
        self.assertEqual(opts[19], b'\x05')
        self.assertEqual(opts[2].hex(), '000100010a0b0c0d')
        self.assertEqual(opts[11][:3], b'\x03\x01\x00')
        self.assertEqual(opts[11][11], 2)
        self.assertEqual(opts[11][12:], hmac.new(key, packet[:-16] + bytes(16), hashlib.md5).digest())
        replay = int.from_bytes(opts[11][3:11], 'big')
        self.service.close()
        self.service = self.create_service()
        self.assertEqual(dict(options(self.enroll()))[11][12:], key)
        self.service.trigger()
        self.service.poll()
        packet = self.sock.sendto.call_args.args[0]
        self.assertGreater(int.from_bytes(dict(options(packet[4:]))[11][3:11], 'big'), replay)

    @patch('socket.if_nametoindex', return_value=7)
    def test_bounded_retries_and_successful_renew_acknowledges(self, _index):
        self.enroll()
        self.service.trigger()
        self.service.poll()
        self.service.poll()
        self.assertEqual(self.sock.sendto.call_count, 1)
        self.now += 3
        self.service.poll()
        self.assertEqual(self.sock.sendto.call_count, 2)
        self.transaction.last_message_received_type = 5
        self.service.reply_options(self.transaction, reply(status=2))
        self.now += 5
        self.service.poll()
        self.assertEqual(self.sock.sendto.call_count, 3)
        self.service.reply_options(self.transaction, reply())
        self.now += 100
        self.service.poll()
        self.assertEqual(self.sock.sendto.call_count, 3)
        self.service.trigger()
        for _ in range(20):
            self.service.poll()
            self.now += 101
        self.assertEqual(self.sock.sendto.call_count, 11)

    def test_expiry_and_server_identity_isolation(self):
        self.enroll()
        self.now += 3601
        self.service.trigger()
        self.service.poll()
        self.sock.sendto.assert_not_called()
        self.now = 1000
        self.service.close()
        self.service = self.create_service(server='aabbccdd')
        self.service.trigger()
        self.service.poll()
        self.sock.sendto.assert_not_called()

    def test_non_link_local_and_unconfigured_interfaces_not_enrolled(self):
        for attribute, value in [('interface', 'wan0'), ('client_llip', '20010db8000000000000000000000001')]:
            original = getattr(self.transaction, attribute)
            setattr(self.transaction, attribute, value)
            self.assertEqual(self.enroll(), b'')
            setattr(self.transaction, attribute, original)

    def test_key_reply_replay_is_strictly_increasing(self):
        first = dict(options(self.enroll()))[11]
        second = dict(options(self.enroll()))[11]
        self.assertEqual(first[12:], second[12:])
        self.assertGreater(int.from_bytes(second[3:11], 'big'), int.from_bytes(first[3:11], 'big'))

    def test_release_revokes_consent_and_pending_retries(self):
        self.enroll()
        self.service.trigger()
        self.transaction.last_message_received_type = 8
        self.service.reply_options(self.transaction, b'\x07\x01\x02\x03' + option(13, b'\x00\x00'))
        self.service.trigger()
        self.assertFalse(self.service.pending)

    def test_failed_pd_with_live_na_does_not_acknowledge_renewal(self):
        self.enroll()
        self.service.trigger()
        self.transaction.last_message_received_type = 5
        for pd in (option(13, b'\x00\x06'), option(26, bytes(25))):
            packet = reply() + option(25, struct.pack('!III', 1, 900, 1800) + pd)
            self.assertEqual(self.service.reply_options(self.transaction, packet), b'')
            self.assertTrue(self.service.pending)

    def test_malformed_packet_is_rejected(self):
        with self.assertRaises(ValueError):
            list(options(b'\x00\x01\x00\x10\x00'))


if __name__ == '__main__':
    unittest.main()
