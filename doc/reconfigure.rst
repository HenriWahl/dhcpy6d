===================
dhcpy6d-reconfigure
===================

-------------------------------------
Authenticated DHCPv6 client renewal
-------------------------------------

:Author: Felix Jacobi
:Date: 2026-10-28
:Version: 1.7.0
:Manual section: 7
:Manual group: System administration

DESCRIPTION
===========

DHCPy6d can send DHCPv6 Reconfigure messages requesting an immediate Renew
(RFC 8415 sections 19 and 20.4). This is opt-in on the server::

    [dhcpy6d]
    reconfigure_state_file = /var/lib/dhcpy6d/reconfigure.sqlite

The directory must already exist and be writable by the configured daemon user.
The SQLite file is created with mode 0600 and contains private authentication
keys. Keep it across restarts and lease-database cleanup. It is independent of
the configured lease backend. An empty setting (the default) disables this
feature. Dry-run mode does not open authentication state or send Reconfigure.

Debian and RPM package installation prepares the private state file with daemon
ownership and mode 0600. Upgrades preserve existing keys and counters. This setup
does not enable the feature or modify existing local configurations; enable it
explicitly with the setting above.

A client must include Reconfigure Accept in its initial Request or Rapid Commit
exchange. DHCPy6d then supplies a random 128-bit per-client/interface key in the
successful Reply. Existing clients need a new initial exchange before they can
be notified; their already-running leases cannot be enrolled retroactively.
For dhcpcd 9.4.1, explicitly enable acceptance with::

    option dhcp6_name_servers, dhcp6_domain_search, dhcp6_rapid_commit
    option dhcp6_reconfigure_accept

Explicit DHCPv6 options disable dhcpcd's automatic IPv4 option mapping; retain
the DNS, domain-search and Rapid Commit requests above as needed.

Keep authentication enabled: do not add ``noauthrequired``. dhcpcd already
implements RKAP; no client source patch or shared secret configuration is needed.

At server startup, clients with unexpired authentication records are asked to
renew. A dynamic ``prefix`` control command triggers the same operation after
applying the new prefix, including recovery of the same prefix. Startup skips
the trigger when a configured dynamic prefix is unavailable. Clients outside
the current interface list and expired records are excluded.

Messages go to each client's link-local address on its recorded interface, UDP
port 546, from the server's existing port-547 socket. Each message is authenticated
with HMAC-MD5 and a fresh replay counter committed before transmission. There are
at most eight attempts, starting at two seconds and backing off to a nominal 64 seconds, with jitter.
Repeated triggers coalesce; successful lease Replies cancel pending attempts.
Release removes the client's record. Keys and counters are scoped to the server
DUID so changing identity cannot reuse another server's negotiated state.

This feature triggers the normal Renew handler; it does not change lease
selection or route-hook behavior. The Docker suite verifies that dhcpcd recovers
a changed IA_PD while retaining a stable IA_NA: withdrawal is followed by a repeated
authenticated prompt and a fresh allocation. Upstream still lacks Renew route-up
hooks for restoring a deleted route to an unchanged valid delegation; that is a
separate known failure in the suite.

Compatibility check
-------------------

The Python tests independently decode packets and verify their HMACs, persistence,
expiry, retries, Release, and Reply integration. The optional C checker also uses
dhcpcd 9.4.1's actual ``dhcp_auth_validate`` function to verify valid messages,
reject replayed and tampered messages, and accept the next packet after reopening
server state. This tests authentication interoperability, not a live DSL outage.

Build dhcpcd 9.4.1 in a temporary directory (no installation required)::

    ./configure --without-udev --without-dev --disable-privsep
    make
    cc -std=c99 -D_GNU_SOURCE -DAUTH -I. -Isrc \
        /path/to/dhcpy6d/tests/dhcpcd_auth_check.c src/auth.o \
        compat/crypt/hmac.o compat/crypt/md5.o compat/crypt/sha256.o \
        -o /tmp/dhcpcd-auth-check

Then run in the DHCPy6d checkout::

    DHCPCD_AUTH_CHECK=/tmp/dhcpcd-auth-check \
        python3 -m unittest tests.test_reconfigure_dhcpcd -v

SEE ALSO
========

**dhcpy6d(8)**, **dhcpy6d.conf(5)**, **dhcpcd.conf(5)**
