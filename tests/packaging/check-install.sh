#!/bin/sh
# Run only in a disposable rootful Docker container, with checkout at /src.
set -eu
[ -f /.dockerenv ] && [ "$(id -u)" = 0 ] || {
    echo 'This installation test requires a disposable rootful Docker container.' >&2
    exit 1
}
package=${1:?path to the built Debian package required}
state=/var/lib/dhcpy6d/reconfigure.sqlite
# Slim images normally discard manuals during dpkg installation.
python3 - <<'PYCODE'
from pathlib import Path
for path in Path('/etc/dpkg/dpkg.cfg.d').glob('*'):
    if path.is_file():
        path.write_text(''.join(line for line in path.read_text().splitlines(keepends=True)
            if not (line.startswith('path-exclude') and '/usr/share/man/' in line)))
PYCODE

# Verify the real Debian postinst, then upgrade with existing authentication data.
dpkg -i "$package" >/tmp/install.log 2>&1 || { cat /tmp/install.log; exit 1; }
[ "$(stat -c '%U:%G %a' "$state")" = 'dhcpy6d:dhcpy6d 600' ]
python3 - <<'PY'
import gzip
import shlex
import sqlite3
with sqlite3.connect('/var/lib/dhcpy6d/reconfigure.sqlite') as db:
    db.execute('CREATE TABLE preserved (value TEXT)')
    db.execute("INSERT INTO preserved VALUES ('synthetic-key-and-replay-state')")
with gzip.open('/usr/share/man/man7/dhcpy6d-reconfigure.7.gz', 'rt') as page:
    header = next(line for line in page if line.startswith('.TH '))
    fields = shlex.split(header.replace(r'\-', '-'))
    assert fields[1].upper() == 'DHCPY6D-RECONFIGURE' and fields[2] == '7', header
PY
printf '\n# Locally maintained configuration\n' >> /etc/dhcpy6d.conf
cp /etc/dhcpy6d.conf /tmp/config-before
checksum=$(sha256sum "$state")
dpkg -i "$package" >/tmp/upgrade.log 2>&1 || { cat /tmp/upgrade.log; exit 1; }
[ "$(sha256sum "$state")" = "$checksum" ]
[ "$(stat -c '%U:%G %a' "$state")" = 'dhcpy6d:dhcpy6d 600' ]
cmp /etc/dhcpy6d.conf /tmp/config-before
for suffix in -journal -wal -shm; do touch "$state$suffix"; done
dpkg --purge dhcpy6d >/tmp/purge.log 2>&1 || { cat /tmp/purge.log; exit 1; }
for suffix in '' -journal -wal -shm; do [ ! -e "$state$suffix" ]; done
printf 'Debian install, upgrade preservation, manpage and purge passed\n'

# Parse the actual RPM spec, then exercise its expanded %post for install/upgrade.
rpmspec --parse --define 'python3_sitelib /usr/lib/python3/dist-packages' \
    --define '_unitdir /lib/systemd/system' --define '__python3 /usr/bin/python3' \
    --define 'py3_build python3 setup.py build' /src/redhat/dhcpy6d.spec >/tmp/rpm-expanded.spec
python3 - <<'PY'
from pathlib import Path
text = Path('/tmp/rpm-expanded.spec').read_text()
start = text.index('\n%post\n') + len('\n%post\n')
end = text.index('\n%preun\n', start)
Path('/tmp/rpm-post.sh').write_text(text[start:end])
assert '%ghost %attr(0600,dhcpy6d,dhcpy6d) /var/lib/dhcpy6d/reconfigure.sqlite' in text
PY
install -D -m 0644 /src/scripts/setup-reconfigure-state /usr/share/dhcpy6d/setup-reconfigure-state
sh -n /tmp/rpm-post.sh
install -d -m 0770 -o dhcpy6d -g dhcpy6d /var/lib/dhcpy6d
sh -e /tmp/rpm-post.sh 1
[ "$(stat -c '%U:%G %a' "$state")" = 'dhcpy6d:dhcpy6d 600' ]
printf 'preserve-existing-rpm-keys' > "$state"
checksum=$(sha256sum "$state")
sh -e /tmp/rpm-post.sh 2
[ "$(sha256sum "$state")" = "$checksum" ]
[ "$(stat -c '%U:%G %a' "$state")" = 'dhcpy6d:dhcpy6d 600' ]
printf 'RPM spec parsing and install/upgrade scriptlets passed\n'
