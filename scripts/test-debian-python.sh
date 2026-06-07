#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required to run Debian Python compatibility tests." >&2
    exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$#" -gt 0 ]; then
    suites=("$@")
else
    suites=(stable oldstable)
fi

for suite in "${suites[@]}"; do
    image="debian:${suite}"
    echo "==> Testing ${image}"

    docker run --rm \
        -e DEBIAN_FRONTEND=noninteractive \
        -v "${repo_root}:/src:ro" \
        "${image}" \
        bash -euxc '
            apt-get update
            apt-get install -y --no-install-recommends python3 ca-certificates

            mkdir -p /work
            cp -a /src/dhcpy6d /src/tests /src/main.py /src/setup.py /work/
            cd /work

            python3 --version
            python3 -m compileall -q dhcpy6d tests main.py setup.py
            python3 -Wd -m unittest -q
        '
done
