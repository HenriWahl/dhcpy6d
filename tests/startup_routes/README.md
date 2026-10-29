Run `bash scripts/test-startup-routes.sh` with Docker. The privileged disposable
container uses `--network none`; it does not change host interfaces.

The test seeds a legacy fixed-prefix lease, starts the daemon with no DHCP
clients, and verifies real kernel routes and SQLite state. It checks retaining
an existing route, restoring a missing route on restart, and removing a route
when its fixed assignment changes. Logs and database evidence are copied to
`startup-route-artifacts/`. Unit tests also cover expired leases, assignment
length/class changes, identity ambiguity, SQL client configuration, and named
prefix pools.

Existing installations need no lease database reset. Fixed client prefixes are
validated against current client configuration before named-pool validation.
