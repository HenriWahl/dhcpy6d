# DHCPv6 interoperability in Docker

Run all clients:

```sh
scripts/test-e2e.sh
```

Run one client or case:

```sh
scripts/test-e2e.sh dhcpcd
E2E_SKIP_BUILD=1 E2E_TEST=authenticated_reconfigure scripts/test-e2e.sh dhcpcd
```

Requirements: Linux, Docker Engine, and permission to run privileged containers.
The container uses `--network none`, a read-only checkout, and container-private
network namespaces linked by veth pairs. It never uses host networking, mounts
host `/sys`, or receives the Docker socket. Privilege is needed to create network
namespaces and run real DHCP clients; it is confined to this disposable container.
Run this on a disposable CI/development runner, as with other privileged tests.

The image uses Debian bookworm packages. Exact installed versions accompany every
run. The server is the current checkout, not an installed package. No client or
server is mocked. Packet capture starts before either endpoint, and assertions
independently decode DHCPv6 TLVs. Tests inspect actual client kernel addresses,
server lease persistence and prefix route hooks in addition to packet exchanges.
Kea perfdhcp simulates clients and therefore does not configure kernel addresses.

## Matrix

| Scenario | Kea perfdhcp | ISC dhclient | dhcpcd | systemd-networkd |
| --- | --- | --- | --- | --- |
| Address, DNS and search options | Yes | Yes | Yes | Yes |
| Address plus delegated prefix and route hook | Yes | Yes | Yes | Yes |
| Rapid Commit | Yes | Explicit skip | Yes | Yes |
| Renew | Yes | Yes | Yes | Yes |
| Rebind after server outage | Tool limitation | Yes | Yes | Yes |
| Release and persisted lease state | Generated traffic | Yes | Yes | Not implemented in systemd 252 |
| Server restart / lease continuity | Yes | Yes | Yes | Yes |
| Prefix control / subsequent allocation | Yes | Yes | Yes | Yes |
| Live mixed-IA prefix renumbering with authenticated retries | — | — | Yes | — |
| Deleted delegated route restored by Renew | — | — | Known server gap | — |
| Authenticated Reconfigure, immediate Renew and replay progression after restart | No RKAP client | Not enabled | Yes | Not enabled |
| Kea relay-forward simulation | Known server gap | — | — | — |
| ISC dhcrelay between separate upstream/downstream links | — | Known server gap | Known server gap | Known server gap |

Kea is a server suite. Its `perfdhcp` tool drives direct exchanges and generates
encapsulated relay-forward messages with `-A 1`; it is not a standalone relay.
ISC dhcrelay is tested as a real process in a third namespace. These relay tests
first require an observed Relay-forward packet, then report the current server's
missing relay handling as a **known failure**. Setup errors or failure to generate
relay traffic fail normally. A working relayed exchange causes an unexpected
success failure until the known-gap marker is removed after review.

Reconfigure enrollment requires an initial Request/Reply or Rapid Commit exchange.
The authenticated test sets T1 to 120 seconds and requires the real dhcpcd client
to send Renew within eight seconds of a signed Reconfigure, excluding timer-driven
renewal. It independently checks the HMAC and increasing counter after restart, and requires
rejection of a tampered newer-counter message and an exact replay without Renew.

Live renumbering retains a stable IA_NA while changing the IA_PD prefix. With
real dhcpcd, the first Renew withdraws the old PD; a repeated authenticated prompt
causes a fresh allocation. The test requires the replacement prefix in packets
and the actual new delegated-prefix route in the client kernel. This does not
prove equivalent behavior in clients that do not implement RKAP.

Deleting an existing server-side delegated route and renewing the same prefix
still demonstrates the independent missing Renew route-up hook on this upstream
branch. This is a narrowly checked known failure; the route hook exists separately
in the NMU branch. The suite records that limitation rather than calling it a pass.

## Evidence and CI

`e2e-artifacts/` contains JUnit XML, client/package versions, server/client/relay
logs, packet JSONL and PCAP files, final namespace address/route state, and the
lease databases. These are synthetic test identities/keys only. Each case has its
own directory and fresh namespaces/state. All processes and the disposable
container are cleaned up even when a test fails. No daemon or interface is created
on the host network.

The GitHub Actions `DHCPv6 interoperability` workflow runs four independent matrix
jobs on an Ubuntu runner with Docker, preserves evidence even on failure, and
keeps capability skips/known failures visible in JUnit and the test output.
