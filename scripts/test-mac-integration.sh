#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image=dhcpy6d-mac-integration:local
artifacts="${MAC_TEST_ARTIFACTS:-$root/mac-test-artifacts}"
mkdir -p "$artifacts"
docker build -t "$image" -f "$root/tests/integration/Dockerfile" "$root"
container=$(docker create --privileged --network none --mount "type=bind,src=$root,dst=/src,readonly" --tmpfs /run "$image")
trap 'docker rm -f "$container" >/dev/null' EXIT
docker start -a "$container" || true
status=$(docker inspect -f '{{.State.ExitCode}}' "$container")
docker cp "$container:/artifacts/." "$artifacts/"
exit "$status"
