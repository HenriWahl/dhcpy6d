"""Authenticated DHCPv6 Reconfigure (RFC 8415 sections 19 and 20.4).

The private state database is separate from the lease database so authentication
keys and replay counters survive lease cleanup and work with every lease backend.
"""
import hashlib
import hmac
import ipaddress
import os
import secrets
import socket
import sqlite3
import struct
import threading
import time


service = None


def option(code, value):
    return struct.pack('!HH', code, len(value)) + value


def options(data):
    """Decode complete TLVs, rejecting truncated options."""
    while data:
        if len(data) < 4:
            raise ValueError('truncated DHCPv6 option header')
        code, length = struct.unpack('!HH', data[:4])
        if len(data) < 4 + length:
            raise ValueError('truncated DHCPv6 option value')
        yield code, data[4:4 + length]
        data = data[4 + length:]


def reply_lifetime(data):
    """Return longest live IA_NA/IA_PD lifetime, or zero for failed Replies."""
    lifetimes = []
    for code, value in options(data):
        if code == 13 and (len(value) < 2 or value[:2] != b'\x00\x00'):
            return 0
        if code not in (3, 25):
            continue
        if len(value) < 12:
            return 0
        ia_lifetimes = []
        for subcode, subvalue in options(value[12:]):
            if subcode == 13 and (len(subvalue) < 2 or subvalue[:2] != b'\x00\x00'):
                return 0
            if code == 3 and subcode == 5 and len(subvalue) >= 24:
                ia_lifetimes.append(struct.unpack('!I', subvalue[20:24])[0])
            elif code == 25 and subcode == 26 and len(subvalue) >= 25:
                ia_lifetimes.append(struct.unpack('!I', subvalue[4:8])[0])
        # A stable IA_NA must not hide a failed/withdrawn delegated prefix.
        if not max(ia_lifetimes, default=0):
            return 0
        lifetimes.extend(ia_lifetimes)
    return max(lifetimes, default=0)


class ReconfigureService(threading.Thread):
    """Track consenting clients and send bounded, authenticated Renew triggers."""
    MAX_ATTEMPTS = 8

    def __init__(self, path, server_duid, sock, interfaces, log, clock=time.time):
        super().__init__(name='reconfigure', daemon=True)
        self.server_duid = server_duid.lower()
        self.sock = sock
        self.interfaces = set(interfaces)
        self.log = log
        self.clock = clock
        self.lock = threading.RLock()
        self.stopped = threading.Event()
        self.pending = {}
        # Create the file privately before SQLite opens it. Never follow symlinks.
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute('''CREATE TABLE IF NOT EXISTS clients (
            server TEXT NOT NULL, duid TEXT NOT NULL, interface TEXT NOT NULL,
            address TEXT NOT NULL, key BLOB NOT NULL, replay INTEGER NOT NULL,
            expires INTEGER NOT NULL, PRIMARY KEY (server, duid, interface))''')
        self.db.commit()

    def close(self):
        self.stopped.set()
        if self.is_alive():
            self.join()
        with self.lock:
            self.db.close()

    def reply_options(self, transaction, response):
        """Provision RKAP in initial Replies; acknowledge successful renewals.

        Called only for the final Reply, after all normal error handling. Never
        include keys in logs, Advertise, errors, or replies without live leases.
        """
        if len(response) < 4 or response[0] != 7:
            return b''
        if transaction.interface not in self.interfaces:
            return b''
        address = ipaddress.IPv6Address(int(transaction.client_llip, 16))
        if not address.is_link_local:
            return b''
        duid = transaction.duid.lower()
        bytes.fromhex(duid)
        identity = (self.server_duid, duid, transaction.interface)
        initial = transaction.last_message_received_type in (1, 3)
        if transaction.last_message_received_type == 8:
            status = dict(options(response[4:])).get(13)
            if status is not None and len(status) >= 2 and status[:2] == b'\x00\x00':
                with self.lock, self.db:
                    self.db.execute('DELETE FROM clients WHERE server=? AND duid=? AND interface=?', identity)
                    self.pending.pop(identity, None)
            return b''
        lifetime = reply_lifetime(response[4:])
        if not lifetime:
            return b''
        with self.lock, self.db:
            row = self.db.execute('SELECT key, replay FROM clients WHERE server=? AND duid=? AND interface=?',
                                  identity).fetchone()
            if initial and transaction.options.get(20) != '':
                self.db.execute('DELETE FROM clients WHERE server=? AND duid=? AND interface=?', identity)
                self.pending.pop(identity, None)
                return b''
            if row is None and not initial:
                return b''
            key, replay = row if row else (secrets.token_bytes(16), 0)
            if initial:
                replay += 1
            self.db.execute('INSERT OR REPLACE INTO clients VALUES (?, ?, ?, ?, ?, ?, ?)',
                            (*identity, str(address), key, replay, int(self.clock()) + lifetime))
            self.pending.pop(identity, None)
            if not initial:
                return b''
            # Protocol 3, HMAC-MD5 algorithm 1, counter RDM 0, key type 1.
            auth = b'\x03\x01\x00' + struct.pack('!Q', replay) + b'\x01' + key
            return option(20, b'') + option(11, auth)

    def trigger(self):
        """Queue currently consenting, unexpired clients; coalesce repeated triggers."""
        with self.lock, self.db:
            now = self.clock()
            self.db.execute('DELETE FROM clients WHERE expires <= ?', (int(now),))
            for duid, interface in self.db.execute(
                    'SELECT duid, interface FROM clients WHERE server=?', (self.server_duid,)):
                if interface in self.interfaces:
                    self.pending.setdefault((self.server_duid, duid, interface), (now, 0))

    def poll(self):
        """Send due attempts. Persist a fresh replay value before every send."""
        with self.lock:
            now = self.clock()
            for identity, (due, attempts) in list(self.pending.items()):
                if due > now:
                    continue
                row = self.db.execute('SELECT address, key, replay, expires FROM clients '
                                      'WHERE server=? AND duid=? AND interface=?', identity).fetchone()
                if row is None or row[3] <= now or attempts >= self.MAX_ATTEMPTS:
                    del self.pending[identity]
                    continue
                address, key, replay, _expires = row
                # One retry gets its own counter and HMAC, even if the last send failed.
                replay += 1
                with self.db:
                    self.db.execute('UPDATE clients SET replay=? WHERE server=? AND duid=? AND interface=?',
                                    (replay, *identity))
                packet = (b'\x0a\x00\x00\x00' + option(2, bytes.fromhex(self.server_duid)) +
                          option(1, bytes.fromhex(identity[1])) + option(19, b'\x05') +
                          option(11, b'\x03\x01\x00' + struct.pack('!Q', replay) + b'\x02' + bytes(16)))
                digest = hmac.new(key, packet, hashlib.md5).digest()
                packet = packet[:-16] + digest
                # RFC 8415 retransmission jitter prevents synchronized renew storms.
                delay = min(2 ** (attempts + 1), 64) * (0.9 + secrets.randbelow(201) / 1000)
                self.pending[identity] = (now + delay, attempts + 1)
                try:
                    index = socket.if_nametoindex(identity[2])
                    self.sock.sendto(packet, (address, 546, 0, index))
                    self.log.info(f'Reconfigure Renew sent to {address}%{identity[2]} (attempt {attempts + 1})')
                except OSError as error:
                    self.log.warning(f'Reconfigure send failed on {identity[2]}: {error}')

    def run(self):
        while not self.stopped.wait(0.25):
            try:
                self.poll()
            except Exception as error:
                self.log.error(f'Reconfigure worker failed: {error}')
