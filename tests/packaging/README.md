# Package installation checks

Run in a disposable Linux Docker container; the script refuses to run outside
Docker or without root. Build a Debian package first, then:

```sh
docker build -t dhcpy6d-packaging-check -f tests/packaging/Dockerfile .
package="$(readlink -f ../dhcpy6d_$(dpkg-parsechangelog -SVersion)_all.deb)"
docker run --rm --network none \
  --mount "type=bind,src=$PWD,dst=/src,readonly" \
  --mount "type=bind,src=$package,dst=/tmp/package.deb,readonly" \
  dhcpy6d-packaging-check sh /src/tests/packaging/check-install.sh /tmp/package.deb
```

The test performs real Debian install, reinstall/upgrade and purge operations.
It verifies private state ownership/mode, preserved state bytes and local config,
the installed section-7 manual, and cleanup on purge. It also parses the RPM spec
with `rpmspec` and executes the expanded `%post` scriptlet twice to check state
preservation. This validates RPM scriptlet behavior, not a full RPM build/install.
No service is started and no production state is mounted.
