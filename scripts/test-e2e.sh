#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${E2E_IMAGE:-dhcpy6d-e2e:local}"
artifacts="${E2E_ARTIFACTS:-${repo_root}/e2e-artifacts}"
mkdir -p "$artifacts"
if [[ "${E2E_SKIP_BUILD:-0}" != 1 ]]; then
    docker build -t "$image" -f "$repo_root/tests/e2e/Dockerfile" "$repo_root"
fi
clients=("$@")
if [[ ${#clients[@]} == 0 ]]; then
    clients=(kea dhclient dhcpcd networkd)
fi
container_id=''
cleanup() {
    if [[ -n "$container_id" ]]; then
        docker rm -f "$container_id" >/dev/null
    fi
}
trap cleanup EXIT INT TERM
status=0
for client in "${clients[@]}"; do
    extra=()
    if [[ -n "${E2E_TEST:-}" ]]; then
        extra=(--test "$E2E_TEST")
    fi
    # All namespaces, veths and capabilities belong to this disposable container.
    container_id="$(docker create --privileged --network none \
        --mount "type=bind,src=${repo_root},dst=/src,readonly" \
        --tmpfs /run --tmpfs /tmp \
        "$image" --client "$client" "${extra[@]}")"
    docker start -a "$container_id" || true
    code="$(docker inspect --format '{{.State.ExitCode}}' "$container_id")"
    docker cp "$container_id:/artifacts/." "$artifacts/"
    if [[ "$code" != 0 ]]; then
        status=1
    fi
    cleanup
    container_id=''
done
exit "$status"
