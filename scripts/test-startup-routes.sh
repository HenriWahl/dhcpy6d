#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image=dhcpy6d-startup-routes:local
artifacts="${STARTUP_TEST_ARTIFACTS:-$root/startup-route-artifacts}"
mkdir -p "$artifacts"
docker build -t "$image" -f "$root/tests/startup_routes/Dockerfile" "$root"
container=$(docker create --privileged --network none --mount "type=bind,src=$root,dst=/src,readonly" --tmpfs /run "$image")
trap 'docker rm -f "$container" >/dev/null' EXIT
docker start -a "$container" || true
status=$(docker inspect -f '{{.State.ExitCode}}' "$container")
docker cp "$container:/artifacts/." "$artifacts/"
exit "$status"
