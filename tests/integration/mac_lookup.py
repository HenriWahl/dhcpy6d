"""Two isolated links, each with fe80::2, exercise actual kernel NDP and DHCP."""
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
import unittest
import xml.etree.ElementTree as ET

ARTIFACTS = Path('/artifacts')
SERVER_ROOT = Path(os.environ.get('MAC_TEST_SERVER_ROOT', '/src'))


def run(*args, ns=None):
    try:
        return subprocess.check_output((['ip', 'netns', 'exec', ns] if ns else []) + list(args),
                                       text=True, stderr=subprocess.STDOUT, timeout=30)
    except subprocess.CalledProcessError as error:
        raise AssertionError(error.output) from error


class ScopedMacLookup(unittest.TestCase):
    def test_same_link_local_address_on_separate_interfaces(self):
        self.assertTrue(Path('/.dockerenv').exists(), 'run in the disposable test container')
        ARTIFACTS.mkdir(exist_ok=True)
        processes = []
        handles = []
        namespaces = []

        def spawn(args, ns, name):
            handle = (ARTIFACTS / name).open('w')
            handles.append(handle)
            proc = subprocess.Popen(['ip', 'netns', 'exec', ns] + args, stdout=handle, stderr=subprocess.STDOUT)
            processes.append(proc)
            return proc

        try:
            for ns in ('server', 'client0', 'client1'):
                run('ip', 'netns', 'add', ns)
                namespaces.append(ns)
                run('ip', 'link', 'set', 'lo', 'up', ns=ns)
            macs = ['02:00:00:00:00:11', '02:00:00:00:00:22']
            for i, mac in enumerate(macs):
                run('ip', 'link', 'add', f's{i}', 'type', 'veth', 'peer', 'name', f'c{i}')
                run('ip', 'link', 'set', f's{i}', 'netns', 'server')
                run('ip', 'link', 'set', f'c{i}', 'netns', f'client{i}')
                run('ip', 'link', 'set', f's{i}', 'name', f'lan{i}', ns='server')
                run('ip', 'link', 'set', f'c{i}', 'name', 'eth0', ns=f'client{i}')
                run('ip', 'link', 'set', 'eth0', 'address', mac, ns=f'client{i}')
                for ns, interface, address in [('server', f'lan{i}', 'fe80::1'), (f'client{i}', 'eth0', 'fe80::2')]:
                    run('ip', 'link', 'set', interface, 'up', ns=ns)
                    run('ip', '-6', 'addr', 'replace', address + '/64', 'dev', interface, 'nodad', ns=ns)
                run('ping', '-6', '-c', '1', '-W', '2', 'fe80::1%eth0', ns=f'client{i}')
            neighbours = json.loads(run('ip', '-j', '-6', 'neigh', 'show', ns='server'))
            (ARTIFACTS / 'neighbours.json').write_text(json.dumps(neighbours, indent=2))
            self.assertEqual({(row['dev'], row.get('lladdr')) for row in neighbours if row['dst'] == 'fe80::2'},
                             {('lan0', macs[0]), ('lan1', macs[1])})
            spawn(['tcpdump', '-ni', 'any', '-U', '-w', str(ARTIFACTS / 'packets.pcap'), 'udp port 546 or udp port 547'], 'server', 'tcpdump.log')
            (ARTIFACTS / 'leases.sqlite').touch()
            conf = ARTIFACTS / 'server.conf'
            conf.write_text(f'''[dhcpy6d]
interface = lan0 lan1
store_config = none
store_sqlite_volatile = {ARTIFACTS}/leases.sqlite
identification = mac
ignore_mac = no
cache_mac_llip = yes
really_do_it = yes
log = yes
log_console = yes
log_mac_llip = yes
serverduid = 0001000100010000020000000001
[class_default]
addresses = pool
[address_pool]
category = eui64
pattern = 2001:db8:1::$eui64$
''')
            expected = ['2001:db8:1::ff:fe00:11', '2001:db8:1::ff:fe00:22']
            for cycle in range(2):
                server = spawn(['python3', str(SERVER_ROOT / 'main.py'), '-c', str(conf)], 'server', f'server-{cycle}.log')
                for _ in range(100):
                    if 'Listening on interfaces' in (ARTIFACTS / f'server-{cycle}.log').read_text():
                        break
                    self.assertIsNone(server.poll(), (ARTIFACTS / f'server-{cycle}.log').read_text())
                    time.sleep(.1)
                else:
                    self.fail('server never became ready')
                # Reverse order after restart to expose whichever neighbour wins.
                for i in ([0, 1, 0] if cycle == 0 else [1, 0, 1]):
                    result = json.loads(run('python3', '/src/tests/integration/client.py', macs[i], ns=f'client{i}'))
                    (ARTIFACTS / f'reply-{cycle}-{i}.json').write_text(json.dumps(result))
                    self.assertEqual(result['addresses'], [expected[i]], result)
                with sqlite3.connect(ARTIFACTS / 'leases.sqlite') as db:
                    rows = db.execute('SELECT interface, mac, link_local_ip FROM macs_llips ORDER BY interface').fetchall()
                    self.assertEqual(rows, [('lan0', macs[0], ipaddress.IPv6Address('fe80::2').exploded.replace(':', '')),
                                            ('lan1', macs[1], ipaddress.IPv6Address('fe80::2').exploded.replace(':', ''))])
                server.terminate()
                server.wait(timeout=5)
        finally:
            for proc in reversed(processes):
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
            for handle in handles:
                handle.close()
            for ns in reversed(namespaces):
                subprocess.run(['ip', 'netns', 'del', ns], check=False)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ScopedMacLookup)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = ET.Element('testsuite', name='interface-scoped-mac', tests=str(result.testsRun),
                        failures=str(len(result.failures)), errors=str(len(result.errors)))
    case = ET.SubElement(report, 'testcase', name='same_link_local_on_separate_interfaces')
    for test, detail in result.failures + result.errors:
        ET.SubElement(case, 'failure').text = detail
    ET.ElementTree(report).write(ARTIFACTS / 'junit.xml', encoding='utf-8', xml_declaration=True)
    raise SystemExit(not result.wasSuccessful())
