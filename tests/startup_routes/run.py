"""Exercise daemon startup and kernel routes without any DHCP client running."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time

ROOT = Path(os.environ.get('STARTUP_SERVER_ROOT', '/src'))
ART = Path('/artifacts')
ART.mkdir(exist_ok=True)
assert Path('/.dockerenv').exists(), 'Run only in the disposable container'


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


run('ip', 'link', 'add', 'lan0', 'type', 'dummy')
run('ip', 'link', 'set', 'lan0', 'up')
run('ip', '-6', 'addr', 'add', 'fe80::1/64', 'dev', 'lan0', 'nodad')
prefix = '20010db8001000b00000000000000000'
route = '2001:db8:10:b0::/60'
clients = ART / 'clients.conf'
clients.write_text('[client]\nhostname = client\nmac = 02:00:00:00:00:02\nclass = fixed_lan\nprefix = ' + route + '\n')
conf = ART / 'server.conf'
conf.write_text(f"""[dhcpy6d]
interface = lan0
store_config = file
store_file_config = {clients}
store_sqlite_volatile = {ART}/leases.sqlite
identification = mac
really_do_it = yes
manage_routes_at_start = yes
log = yes
log_console = yes
serverduid = 0001000100010000020000000001
[class_fixed_lan]
interface = lan0
addresses =
advertise = prefixes
call_up = python3 /src/tests/startup_routes/hook.py up $prefix$/$length$ $router$
call_down = python3 /src/tests/startup_routes/hook.py down $prefix$/$length$ $router$
""")
with sqlite3.connect(ART / 'leases.sqlite') as db:
    db.executescript((ROOT / 'doc/volatile.sql').read_text())
    columns = [row[1] for row in db.execute('pragma table_info(prefixes)')]
    values = dict.fromkeys(columns, 0)
    values.update(prefix=prefix, length=60, active=1, hostname='client', type='default',
                  category='range', mac='02:00:00:00:00:02', duid='0001',
                  valid_until=int(time.time())+7200, **{'class': 'fixed_lan'})
    db.execute('insert into prefixes values (' + ','.join('?' for _ in columns) + ')', [values[c] for c in columns])
    db.execute('insert into routes values (?,60,?,0)', (prefix, 'fe800000000000000000000000000002'))
run('ip', '-6', 'route', 'replace', route, 'via', 'fe80::2', 'dev', 'lan0')
for cycle in range(3):
    if cycle == 1:
        # The kernel lost its route; startup must restore it from the lease DB.
        run('ip', '-6', 'route', 'del', route)
    if cycle == 2:
        clients.write_text(clients.read_text().replace(route, '2001:db8:10:c0::/60'))
    hook = ART / 'hooks.log'
    hook.write_text('')
    logfile = ART / f'server-{cycle}.log'
    with logfile.open('w') as output:
        process = subprocess.Popen(['python3', str(ROOT / 'main.py'), '-c', str(conf)], stdout=output, stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                text = logfile.read_text()
                if 'Listening on interfaces' in text and hook.read_text():
                    time.sleep(.2)
                    break
                assert process.poll() is None, text
                time.sleep(.1)
            else:
                raise AssertionError(logfile.read_text())
            events = hook.read_text().splitlines()
            expected = 'down' if cycle == 2 else 'up'
            assert len(events) == 1 and events[0].startswith(expected + ' '), events
            routes = json.loads(run('ip', '-j', '-6', 'route', 'show', route))
            (ART / f'routes-{cycle}.json').write_text(json.dumps(routes, indent=2))
            assert bool(routes) == (cycle != 2), routes
            with sqlite3.connect(ART / 'leases.sqlite') as db:
                assert db.execute('select active from prefixes').fetchone() == ((0,) if cycle == 2 else (1,))
                assert db.execute('select count(*) from routes').fetchone() == ((0,) if cycle == 2 else (1,))
        finally:
            process.terminate()
            process.wait(timeout=10)
print('PASS: retained fixed route, restored missing kernel route, removed changed assignment; no DHCP clients')
