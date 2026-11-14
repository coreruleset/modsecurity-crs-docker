#!/usr/bin/env bash
# Verifies server-side mutual TLS of a target: generates the test certificates
# (tests/setup-mtls.sh), starts the stack in tests/docker-compose.mtls.yml and
# runs tests/verify-mtls.sh against it. The stack and the certificates are
# removed afterwards.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tests/verify-server-mtls.sh <target>

  target  Build target, e.g. nginx-debian-writable-latest. The image
          <target>-verification has to exist locally.
EOF
}

target="${1:-${TARGET:-}}"
if [ -z "${target}" ]; then
  usage >&2
  exit 2
fi

cd "$(dirname "${0}")/.."

compose_file="tests/docker-compose.mtls.yml"

# cleanup: on failure, print the compose logs, so that a failing assertion still
# leaves diagnostics, then tear the stack down and remove what setup-mtls.sh wrote
cleanup() {
  local status=$?
  if [ "${status}" -ne 0 ]; then
    docker compose -f "${compose_file}" logs || true
  fi
  docker compose -f "${compose_file}" down -vt 0
  rm -rf tests/mtls-certs tests/.env
}
trap cleanup EXIT

./tests/setup-mtls.sh "${target}"
docker compose -f "${compose_file}" up -d
./tests/verify-mtls.sh
