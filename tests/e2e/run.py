#!/usr/bin/env python3
"""Real-process DHCPv6 interoperability tests in container-private namespaces."""
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import time
import unittest
import xml.etree.ElementTree as ET

ROOT = Path('/src')
ARTIFACTS = Path('/artifacts')
CLIENT = 'dhcpcd'


class KnownGap(Exception):
    pass


def command(*args, ns=None, check=True):
    argv = (['ip', 'netns', 'exec', ns] if ns else []) + list(args)
    return subprocess.run(argv, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=25)


def tlvs(data):
    result = []
    while data:
        if len(data) < 4:
            raise AssertionError('truncated option header')
        code, length = struct.unpack('!HH', data[:4])
        if len(data) < length + 4:
            raise AssertionError('truncated option body')
        result.append((code, data[4:4 + length]))
        data = data[4 + length:]
    return result


def inner(event):
    data = bytes.fromhex(event['hex'])
    while data[0] in (12, 13):
        data = dict(tlvs(data[34:]))[9]
    return data


def resources(event, kind):
    values = []
    for code, value in tlvs(inner(event)[4:]):
        if code != kind:
            continue
        for subcode, sub in tlvs(value[12:]):
            if kind == 3 and subcode == 5:
                values.append((str(ipaddress.IPv6Address(sub[:16])), int.from_bytes(sub[20:24], 'big')))
            if kind == 25 and subcode == 26:
                values.append((str(ipaddress.IPv6Network((ipaddress.IPv6Address(sub[9:25]), sub[8]))), int.from_bytes(sub[4:8], 'big')))
    return values


class Lab:
    def __init__(self, directory, relay=False):
        self.directory = directory
        self.processes = []
        self.handles = []
        self.server = None
        self.client = None
        self.relay = relay
        self.relay_process = None
        for state in ('/work', '/var/lib/dhcpcd', '/var/lib/dhcpcd5', '/run/systemd/netif', '/var/lib/dhcp', '/run/dhcpcd', '/run/dhcpcd5'):
            shutil.rmtree(state, ignore_errors=True)
        Path('/work').mkdir()
        for ns in ('server', 'client') + (('relay',) if relay else ()):
            command('ip', 'netns', 'add', ns)
            command('ip', 'link', 'set', 'lo', 'up', ns=ns)
        command('ip', 'link', 'add', 'srv', 'type', 'veth', 'peer', 'name', 'cli')
        command('ip', 'link', 'set', 'srv', 'netns', 'server')
        command('ip', 'link', 'set', 'cli', 'netns', 'relay' if relay else 'client')
        self.interface('server', 'srv', 'fe80::1')
        self.interface('relay' if relay else 'client', 'cli', 'fe80::2')
        if relay:
            command('ip', 'link', 'add', 'rdown', 'type', 'veth', 'peer', 'name', 'lan')
            command('ip', 'link', 'set', 'rdown', 'netns', 'relay')
            command('ip', 'link', 'set', 'lan', 'netns', 'client')
            self.interface('relay', 'rdown', 'fe80::3')
            self.interface('client', 'lan', 'fe80::4')
            command('ip', '-6', 'addr', 'add', '2001:db8:ffff::1/64', 'dev', 'srv', ns='server')
            command('ip', '-6', 'addr', 'add', '2001:db8:ffff::2/64', 'dev', 'cli', ns='relay')
            command('ip', '-6', 'addr', 'add', '2001:db8:eeee::1/64', 'dev', 'rdown', ns='relay')
            self.relay_process = self.spawn(['dhcrelay', '-6', '-d', '-l', 'rdown', '-u', '2001:db8:ffff::1%cli'], 'relay', 'relay.log')
        self.iface = 'lan' if relay else 'cli'
        self.spawn(['python3', str(ROOT / 'tests/e2e/capture.py'), str(directory)], 'server', 'capture.log')
        self.wait(lambda: (directory / 'capture.ready').exists(), 5, 'packet capture startup')
        self.write_config()
        self.start_server()

    @staticmethod
    def interface(ns, iface, address):
        command('ip', 'link', 'set', 'dev', iface, 'addrgenmode', 'none', ns=ns)
        command('ip', 'link', 'set', iface, 'up', ns=ns)
        command('ip', '-6', 'addr', 'flush', 'dev', iface, 'scope', 'link', ns=ns)
        command('ip', '-6', 'addr', 'add', address + '/64', 'dev', iface, 'nodad', ns=ns)
        command('ip', '-6', 'route', 'replace', 'ff00::/8', 'dev', iface, ns=ns)

    def spawn(self, argv, ns, logfile):
        handle = (self.directory / logfile).open('a')
        self.handles.append(handle)
        process = subprocess.Popen(['ip', 'netns', 'exec', ns] + argv, stdout=handle, stderr=subprocess.STDOUT,
                                   start_new_session=True, env={**os.environ, 'PYTHONUNBUFFERED': '1', 'SYSTEMD_LOG_LEVEL': 'debug'})
        self.processes.append(process)
        return process

    @staticmethod
    def stop(process):
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)

    def write_config(self, t1=10, t2=20, lifetime=90):
        Path('/work/server.conf').write_text(f'''[dhcpy6d]
interface = srv
user = root
group = root
ignore_mac = yes
store_config = none
store_sqlite_volatile = /work/leases.sqlite
serverduid = 0001000100010000020000000001
really_do_it = yes
log = yes
log_console = yes
nameserver = 2001:db8::53
domain = e2e.test
domain_search_list = e2e.test
preferred_lifetime = {max(t2 + 1, lifetime // 2)}
valid_lifetime = {lifetime}
t1 = {t1}
t2 = {t2}
cleaning_interval = 1
reconfigure_state_file = /work/reconfigure.sqlite
[class_default]
addresses = pool
prefixes = pd
advertise = addresses prefixes
call_up = /src/tests/e2e/route-hook up $prefix$/$length$ $router$
call_down = /src/tests/e2e/route-hook down $prefix$/$length$ $router$
[address_pool]
category = range
pattern = $prefix$:1::$range$
range = 100-1ff
[prefix_pd]
category = range
pattern = $prefix$:100:$range$::
range = 1-ff
length = 64
route_link_local = yes
''')

    def start_server(self):
        Path('/work/leases.sqlite').touch(exist_ok=True)
        self.server = self.spawn(['python3', '/src/main.py', '-c', '/work/server.conf', '-p', '2001:db8'], 'server', 'server.log')
        def ready():
            if self.server.poll() is not None:
                raise AssertionError('server exited: ' + (self.directory / 'server.log').read_text())
            return '0223' in command('cat', '/proc/net/udp6', ns='server').stdout
        self.wait(ready, 8, 'server port 547')

    def events(self):
        path = self.directory / 'packets.jsonl'
        records = []
        if path.exists():
            for line in path.read_text().splitlines():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # Last line can be in flight while capturing.
        return records

    def wait(self, predicate, timeout=20, description='condition'):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.1)
        raise TimeoutError(f'timeout waiting for {description}; see {self.directory}')

    def packet(self, message, since=0, timeout=20, predicate=lambda event: True):
        return self.wait(lambda: next((e for e in self.events() if e['time'] >= since and
            (e['type'] if message in (12, 13) else inner(e)[0]) == message and predicate(e)), None), timeout, f'DHCPv6 type {message}')

    def start_client(self, pd=True, rapid=False, relay_sim=False, rates=False):
        iface = self.iface
        if CLIENT == 'kea':
            argv = ['perfdhcp', '-6', '-l', iface, '-L', '546', '-r', '2', '-R', '1', '-p', '20',
                    '-e', 'address-and-prefix' if pd else 'address-only', '-o', '6,00170018']
            if relay_sim:
                argv += ['-A', '1']
            if rapid:
                argv += ['-i', '-c']
            if rates:
                argv += ['-f', '1', '-F', '1']
            elif not rapid:
                argv += ['-f', '1']
            argv += ['ff02::1:2']
        elif CLIENT == 'dhclient':
            Path('/var/lib/dhcp').mkdir(parents=True, exist_ok=True)
            Path('/work/dhclient.conf').write_text('timeout 15;\ninitial-interval 1;\nrequest dhcp6.name-servers, dhcp6.domain-search;\n')
            argv = ['dhclient', '-6', '-d', '-v', '-cf', '/work/dhclient.conf', '-lf', '/var/lib/dhcp/dhclient6.leases',
                    '-pf', '/run/dhclient6.pid', '-sf', '/sbin/dhclient-script']
            if pd:
                argv += ['-P', '-N']
            argv += [iface]
        elif CLIENT == 'dhcpcd':
            Path('/work/dhcpcd.conf').write_text(f'''duid 00:01:00:01:00:01:00:00:02:00:00:00:00:02
ipv6only
noipv6rs
nohook resolv.conf,hostname,ntp
option dhcp6_name_servers, dhcp6_domain_search, dhcp6_reconfigure_accept
{'option dhcp6_rapid_commit' if rapid else 'nooption dhcp6_rapid_commit'}
interface {iface}
 ia_na 1
{' ia_pd 1' if pd else ''}
''')
            argv = ['dhcpcd', '-6', '-d', '-B', '-f', '/work/dhcpcd.conf', iface]
        else:
            # networkd normally gets these from tmpfiles/udev under PID 1.
            import pwd
            uid = pwd.getpwnam('systemd-network').pw_uid
            gid = pwd.getpwnam('systemd-network').pw_gid
            for path in ('/run/systemd/netif', '/run/systemd/netif/links', '/run/systemd/netif/leases'):
                Path(path).mkdir(parents=True, exist_ok=True)
                os.chown(path, uid, gid)
            Path('/run/udev/data').mkdir(parents=True, exist_ok=True)
            index = json.loads(command('ip', '-j', 'link', 'show', 'dev', iface, ns='client').stdout)[0]['ifindex']
            Path(f'/run/udev/data/n{index}').write_text('I:1\nE:ID_NET_DRIVER=veth\n')
            Path('/etc/systemd/network').mkdir(parents=True, exist_ok=True)
            Path('/etc/systemd/network/10-e2e.network').write_text(f'''[Match]
Name={iface}
[Network]
DHCP=ipv6
IPv6AcceptRA=no
LinkLocalAddressing=ipv6
[DHCPv6]
WithoutRA=solicit
UseAddress=yes
UseDNS=no
UseNTP=no
RequestOptions=23 24
PrefixDelegationHint={'::/64' if pd else ''}
UseDelegatedPrefix={'yes' if pd else 'no'}
RapidCommit={'yes' if rapid else 'no'}
''')
            argv = ['/lib/systemd/systemd-networkd']
        self.client = self.spawn(argv, 'client', 'client.log')
        return self.client

    def release(self):
        if CLIENT == 'dhclient':
            command('dhclient', '-6', '-P', '-N', '-r', '-lf', '/var/lib/dhcp/dhclient6.leases', '-pf', '/run/dhclient6.pid',
                    '-sf', '/sbin/dhclient-script', self.iface, ns='client', check=False)
        elif CLIENT == 'dhcpcd':
            command('dhcpcd', '-6', '-k', self.iface, ns='client')
        else:
            self.stop(self.client)

    def control(self, prefix):
        command('python3', '-c', "import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.sendto(b'prefix " + prefix + "',('::1',547))", ns='server')

    def inject(self, packet):
        mac = json.loads(command('ip', '-j', 'link', 'show', 'dev', self.iface, ns='client').stdout)[0]['address']
        script = ("from scapy.all import Ether,IPv6,UDP,Raw,sendp,get_if_hwaddr; import sys; "
                  "sendp(Ether(src=get_if_hwaddr('srv'),dst=sys.argv[2])/IPv6(src='fe80::1',dst='fe80::2')/"
                  "UDP(sport=547,dport=546)/Raw(bytes.fromhex(sys.argv[1])),iface='srv',verbose=False)")
        command('python3', '-c', script, packet.hex(), mac, ns='server')

    def rows(self, table):
        with sqlite3.connect('/work/leases.sqlite') as db:
            return db.execute(f'SELECT * FROM {table} WHERE active=1').fetchall()

    def close(self):
        for ns in ('server', 'client', 'relay'):
            result = command('ip', '-j', '-6', 'addr', ns=ns, check=False)
            (self.directory / (ns + '-addresses.json')).write_text(result.stdout)
            result = command('ip', '-6', 'route', ns=ns, check=False)
            (self.directory / (ns + '-routes.txt')).write_text(result.stdout)
        for process in reversed(self.processes):
            self.stop(process)
        for handle in self.handles:
            handle.close()
        if Path('/var/lib/dhcp/dhclient6.leases').exists():
            shutil.copy2('/var/lib/dhcp/dhclient6.leases', self.directory / 'dhclient.leases')
        for name in ('leases.sqlite', 'reconfigure.sqlite', 'routes.log', 'server.conf', 'dhclient.leases'):
            path = Path('/work') / name
            if path.exists():
                shutil.copy2(path, self.directory / name)
        for ns in ('server', 'client', 'relay'):
            # Also reap client helper processes that created their own process group.
            for pid in command('ip', 'netns', 'pids', ns, check=False).stdout.split():
                if pid.isdigit():
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            command('ip', 'netns', 'del', ns, check=False)


class Interoperability(unittest.TestCase):
    def setUp(self):
        self.directory = ARTIFACTS / CLIENT / self._testMethodName
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lab = None

    def tearDown(self):
        if self.lab:
            self.lab.close()

    def lab_start(self, **kwargs):
        self.lab = Lab.__new__(Lab)
        self.lab.__init__(self.directory, **kwargs)
        return self.lab

    def acquire(self, pd=True, rapid=False):
        lab = self.lab_start()
        lab.start_client(pd=pd, rapid=rapid)
        event = lab.packet(7, predicate=lambda e: bool(resources(e, 3)))
        self.assertTrue(all(ipaddress.IPv6Address(a) in ipaddress.IPv6Network('2001:db8:1::/64') and valid > 0 for a, valid in resources(event, 3)))
        response_options = dict(tlvs(inner(event)[4:]))
        self.assertEqual(response_options[23], ipaddress.IPv6Address('2001:db8::53').packed)
        self.assertEqual(response_options[24], b'\x03e2e\x04test\x00')
        if pd:
            event = lab.packet(7, predicate=lambda e: bool(resources(e, 25)))
            self.assertTrue(all(ipaddress.IPv6Network(p).subnet_of(ipaddress.IPv6Network('2001:db8:100::/48')) and valid > 0 for p, valid in resources(event, 25)))
            self.assertTrue(lab.rows('prefixes'))
        self.assertTrue(lab.rows('leases'))
        return lab, event

    def test_address_and_options(self):
        lab, event = self.acquire(pd=False)
        if CLIENT != 'kea':
            address = resources(event, 3)[0][0]
            lab.wait(lambda: address in command('ip', '-j', '-6', 'addr', ns='client').stdout,
                     description='client kernel address installation')

    def test_address_and_prefix(self):
        lab, _event = self.acquire()
        lab.wait(lambda: Path('/work/routes.log').exists(), description='delegated-prefix route hook')
        lab.wait(lambda: 'via fe80::' in command('ip', '-6', 'route', ns='server').stdout,
                 description='delegated-prefix route installed in server kernel')

    def test_rapid_commit(self):
        if CLIENT == 'dhclient':
            self.skipTest('adapter does not force Rapid Commit for this implementation')
        lab, event = self.acquire(rapid=True)
        self.assertIn(14, dict(tlvs(inner(event)[4:])))
        self.assertFalse(any(inner(e)[0] in (2, 3) for e in lab.events()))

    def test_renew(self):
        lab, initial = self.acquire()
        renewed = lab.packet(5, since=initial['time'] + .01)
        reply = lab.packet(7, since=renewed['time'], predicate=lambda e: inner(e)[1:4] == inner(renewed)[1:4])
        self.assertEqual(resources(initial, 25), resources(reply, 25))

    def test_rebind_after_server_outage(self):
        if CLIENT == 'kea':
            self.skipTest('perfdhcp generates Renew/Release, not timer-driven Rebind')
        lab, initial = self.acquire()
        Lab.stop(lab.server)
        rebind = lab.packet(6, since=initial['time'], timeout=40)
        lab.start_server()
        lab.packet(7, since=rebind['time'], predicate=lambda e: bool(resources(e, 25)))

    def test_release(self):
        if CLIENT == 'networkd':
            self.skipTest('systemd 252 DHCPv6 client has no Release implementation')
        if CLIENT == 'kea':
            lab = self.lab_start()
            lab.start_client(rates=True)
            released = lab.packet(8)
        else:
            lab, _ = self.acquire()
            lab.release()
            released = lab.packet(8)
        lab.packet(7, since=released['time'], predicate=lambda e: inner(e)[1:4] == inner(released)[1:4])
        if CLIENT != 'kea':
            lab.wait(lambda: not lab.rows('prefixes') and not lab.rows('leases'),
                     description='released address and prefix inactive in database')
            lab.wait(lambda: 'via fe80::' not in command('ip', '-6', 'route', ns='server').stdout,
                     description='released delegated route removed from server kernel')

    def test_server_restart_preserves_leases(self):
        lab, initial = self.acquire()
        # Stop client timers while checking persistence before any new exchange.
        os.killpg(lab.client.pid, signal.SIGSTOP)
        saved = {table: lab.rows(table) for table in ('leases', 'prefixes')}
        Lab.stop(lab.server)
        since = time.monotonic()
        try:
            lab.start_server()
            self.assertEqual(saved, {table: lab.rows(table) for table in saved})
        finally:
            os.killpg(lab.client.pid, signal.SIGCONT)
        event = lab.packet(7, since=since, predicate=lambda e: bool(resources(e, 25)))
        self.assertEqual(resources(initial, 25), resources(event, 25))

    def test_prefix_control_new_allocation(self):
        lab, _ = self.acquire()
        Lab.stop(lab.client)
        lab.control('2001:db9')
        # Start a fresh exchange: old active state must not mask the new prefix.
        for path in ('/var/lib/dhcp/dhclient6.leases', '/var/lib/dhcpcd', '/var/lib/dhcpcd5'):
            if Path(path).is_dir():
                shutil.rmtree(path)
            else:
                Path(path).unlink(missing_ok=True)
        since = time.monotonic()
        lab.start_client()
        reply = lab.packet(7, since=since, predicate=lambda e: any(a.startswith('2001:db9:') and v > 0 for a, v in resources(e, 3)))
        self.assertTrue(any(p.startswith('2001:db9:') and v > 0 for p, v in resources(reply, 25)))

    def test_authenticated_reconfigure(self):
        if CLIENT != 'dhcpcd':
            self.skipTest('authenticated Reconfigure tested with dhcpcd RKAP implementation')
        lab = self.lab_start()
        Lab.stop(lab.server)
        lab.write_config(t1=120, t2=180, lifetime=240)
        lab.start_server()
        lab.start_client()
        initial = lab.packet(7, predicate=lambda e: 11 in dict(tlvs(inner(e)[4:])))
        key = dict(tlvs(inner(initial)[4:]))[11][12:]
        since = time.monotonic()
        lab.control('2001:db8')
        event = lab.packet(10, since=since, timeout=8)
        packet = inner(event)
        auth = dict(tlvs(packet[4:]))[11]
        self.assertEqual(auth[11], 2)
        self.assertEqual(auth[12:], hmac.new(key, packet[:-16] + bytes(16), hashlib.md5).digest())
        renew = lab.packet(5, since=event['time'], timeout=8)
        lab.packet(7, since=renew['time'], predicate=lambda e: inner(e)[1:4] == inner(renew)[1:4])
        self.assertLess(renew['time'] - since, 8)
        # A newer counter with a bad HMAC and an exact replay must not renew.
        time.sleep(.2)
        tampered = bytearray(packet)
        counter_offset = len(packet) - 28 + 3
        tampered[counter_offset:counter_offset + 8] = (int.from_bytes(auth[3:11], 'big') + 1).to_bytes(8, 'big')
        tampered[-1] ^= 1
        since_bad = time.monotonic()
        lab.inject(bytes(tampered))
        lab.inject(packet)
        time.sleep(2)
        self.assertFalse(any(inner(e)[0] == 5 and e['time'] >= since_bad for e in lab.events()))
        self.assertGreaterEqual((lab.directory / 'client.log').read_text().count('authentication failed'), 2)
        Lab.stop(lab.server)
        since = time.monotonic()
        lab.start_server()
        second = lab.packet(10, since=since, timeout=8)
        self.assertGreater(int.from_bytes(dict(tlvs(inner(second)[4:]))[11][3:11], 'big'), int.from_bytes(auth[3:11], 'big'))
        lab.packet(5, since=second['time'], timeout=8)

    def test_live_prefix_renumber(self):
        if CLIENT != 'dhcpcd':
            self.skipTest('immediate live renumbering requires negotiated Reconfigure')
        lab = self.lab_start()
        Lab.stop(lab.server)
        lab.write_config(t1=120, t2=180, lifetime=240)
        config = Path('/work/server.conf')
        config.write_text(config.read_text().replace('pattern = $prefix$:1::$range$', 'pattern = fd00:1::$range$'))
        lab.start_server()
        lab.start_client()
        initial = lab.packet(7, predicate=lambda e: bool(resources(e, 25)))
        since = time.monotonic()
        lab.control('2001:db9')
        reconfigure = lab.packet(10, since=since, timeout=8)
        lab.packet(5, since=reconfigure['time'], timeout=8)
        replacement = lab.packet(7, since=since, timeout=12, predicate=lambda e:
            any(p.startswith('2001:db9:') and valid > 0 for p, valid in resources(e, 25)))
        new_prefix = next(p for p, valid in resources(replacement, 25) if p.startswith('2001:db9:') and valid > 0)
        lab.wait(lambda: new_prefix in command('ip', '-6', 'route', ns='client').stdout,
                 description='client installs replacement delegated-prefix route')
        lab.wait(lambda: 'fd00:1::100' in command('ip', '-j', '-6', 'addr', ns='client').stdout,
                 description='stable client address remains installed')

    def test_renew_restores_delegated_route(self):
        if CLIENT != 'dhcpcd':
            self.skipTest('immediate route recovery uses dhcpcd Reconfigure')
        lab = self.lab_start()
        Lab.stop(lab.server)
        lab.write_config(t1=120, t2=180, lifetime=240)
        lab.start_server()
        lab.start_client()
        initial = lab.packet(7, predicate=lambda e: bool(resources(e, 25)))
        prefix = resources(initial, 25)[0][0]
        lab.wait(lambda: prefix in command('ip', '-6', 'route', ns='server').stdout, description='initial delegated route')
        command('ip', '-6', 'route', 'del', prefix, ns='server')
        since = time.monotonic()
        lab.control('2001:db8')
        trigger = lab.packet(10, since=since, timeout=8)
        renew = lab.packet(5, since=trigger['time'], timeout=8)
        lab.packet(7, since=renew['time'], predicate=lambda e: bool(resources(e, 25)))
        try:
            lab.wait(lambda: prefix in command('ip', '-6', 'route', ns='server').stdout, 3, 'route restoration after Renew')
        except TimeoutError as error:
            raise KnownGap('upstream Renew handler does not run the delegated-prefix route-up hook') from error

    def test_kea_relay_forward(self):
        if CLIENT != 'kea':
            self.skipTest('Kea perfdhcp relay simulation case')
        lab = self.lab_start()
        lab.start_client(relay_sim=True)
        lab.packet(12, timeout=8)
        try:
            lab.packet(7, timeout=5, predicate=lambda e: e['type'] == 13 and bool(resources(e, 25)))
        except TimeoutError as error:
            self.assertIsNone(lab.server.poll(), 'server crashed while processing relay traffic')
            self.assertIsNone(lab.client.poll(), 'client exited during relay exchange')
            if lab.relay_process is not None:
                self.assertIsNone(lab.relay_process.poll(), 'ISC relay exited during exchange')
            self.assertNotIn('Traceback', (lab.directory / 'server.log').read_text())
            raise KnownGap('dhcpy6d does not implement DHCPv6 relay-forward processing') from error
        self.fail('Relay now works: remove the documented known-gap expectation')

    def test_isc_dhcrelay(self):
        if CLIENT == 'kea':
            self.skipTest('real relay case uses persistent clients; Kea relay simulation is separate')
        lab = self.lab_start(relay=True)
        lab.start_client()
        lab.packet(12, timeout=12)
        try:
            lab.packet(7, timeout=5, predicate=lambda e: e['type'] == 13 and bool(resources(e, 25)))
        except TimeoutError as error:
            self.assertIsNone(lab.server.poll(), 'server crashed while processing relay traffic')
            self.assertIsNone(lab.client.poll(), 'client exited during relay exchange')
            if lab.relay_process is not None:
                self.assertIsNone(lab.relay_process.poll(), 'ISC relay exited during exchange')
            self.assertNotIn('Traceback', (lab.directory / 'server.log').read_text())
            raise KnownGap('dhcpy6d does not implement DHCPv6 relay-forward processing') from error
        self.fail('Relay now works: remove the documented known-gap expectation')


class Report(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cases = []

    def startTest(self, test):
        super().startTest(test)
        self.started = time.monotonic()

    def addSuccess(self, test):
        super().addSuccess(test)
        self.record(test, None, '')

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.record(test, 'failure', self._exc_info_to_string(err, test))

    def addError(self, test, err):
        if isinstance(err[1], KnownGap):
            self.addExpectedFailure(test, err)
            return
        super().addError(test, err)
        self.record(test, 'error', self._exc_info_to_string(err, test))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.record(test, 'skipped', reason)

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.record(test, 'skipped', 'KNOWN UPSTREAM GAP: ' + str(err[1]) + '\n' + self._exc_info_to_string(err, test))

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.record(test, 'failure', 'Known gap now passes: remove expectedFailure after review')

    def record(self, test, status, detail):
        case = ET.Element('testcase', name=test._testMethodName, classname=CLIENT, time=str(time.monotonic() - self.started))
        if status:
            ET.SubElement(case, status).text = detail
        self.cases.append(case)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', choices=['kea', 'dhclient', 'dhcpcd', 'networkd'], required=True)
    parser.add_argument('--test', default='')
    args = parser.parse_args()
    CLIENT = args.client
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    versions = command('dpkg-query', '-W', 'isc-dhcp-client', 'isc-dhcp-relay', 'dhcpcd-base', 'kea-admin', 'systemd').stdout
    (ARTIFACTS / ('versions-' + CLIENT + '.txt')).write_text(versions)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Interoperability)
    if args.test:
        suite = unittest.TestSuite(test for test in suite if args.test in test._testMethodName)
    if suite.countTestCases() == 0:
        parser.error('test filter matched no cases')
    result = unittest.TextTestRunner(verbosity=2, resultclass=Report).run(suite)
    xml = ET.Element('testsuite', name='dhcpy6d-' + CLIENT, tests=str(result.testsRun),
        failures=str(len(result.failures) + len(result.unexpectedSuccesses)), errors=str(len(result.errors)),
        skipped=str(len(result.skipped) + len(result.expectedFailures)))
    xml.extend(result.cases)
    ET.ElementTree(xml).write(ARTIFACTS / ('junit-' + CLIENT + '.xml'), encoding='utf-8', xml_declaration=True)
    sys.exit(not result.wasSuccessful())
