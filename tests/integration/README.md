# Interface-scoped MAC lookup integration test

Run on a Linux Docker runner:

```sh
scripts/test-mac-integration.sh
```

A disposable privileged container with `--network none` creates one server and
two client network namespaces. Each client has the same link-local address
`fe80::2`, but a different MAC, on its own veth link to the server. Real ICMPv6
neighbour discovery populates the kernel neighbour table. No neighbour lookup or
server component is mocked; no host networking or Docker socket is mounted.

Both UDP DHCPv6 clients deliberately use transaction ID `123456`. The server
uses MAC-derived EUI-64 allocation, with MAC lookup required. Assertions verify
each client receives its own DUID and its MAC-derived address. Requests alternate
between links, then reverse order after restarting the server with its persisted
MAC cache. Both scoped database rows must survive. The integration workflow
uploads PCAP, neighbour snapshot, Replies, server logs, SQLite database and JUnit.
This tests MAC identification and transaction isolation using real kernel NDP
and DHCPv6 sockets, rather than the lifecycle of a particular client daemon.

The volatile database schema is now version 4. Upgrade rebuilds only the old
MAC/link-local cache, since its rows contain no interface and cannot safely be
migrated. Existing address/prefix leases and route state are retained. MACs are
learned again from the neighbour cache; subsequent restarts retain their scope.
Unit tests cover scoped storage, replacement and the SQLite schema upgrade.
The generic schema change also applies to MySQL/PostgreSQL; those backends are
not exercised by this Linux/SQLite integration test.
