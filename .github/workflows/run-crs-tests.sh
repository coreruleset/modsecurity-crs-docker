#!/usr/bin/env bash
# Runs the CRS regression tests in ./crs against the image built for a target
# (see prepare-crs-tests.sh), with go-ftw (see install-go-ftw.sh).
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: .github/workflows/run-crs-tests.sh <target>

  target  Build target, e.g. nginx-debian-writable-latest. The CRS checkout in
          ./crs of the repository root has to be prepared, and ./crs/ftw has to
          exist.
EOF
}

target="${1:-${TARGET:-}}"
if [ -z "${target}" ]; then
  usage >&2
  exit 2
fi

cd "$(dirname "${0}")/../.."
variant="$(./tests/target-variant.sh "${target}")"
cd crs

modsec_version="modsec3-nginx"
backend="nginx"
if [ "${variant}" = "apache" ]; then
  modsec_version="modsec2-apache"
  backend="httpd"
fi

compose_file="./tests/docker-compose.yml"

# cleanup: on failure, print the compose logs, then stop the stack on every exit
# path, as both services publish host port 80. The log directories are bind
# mounts and stay.
cleanup() {
  local status=$?
  if [ "${status}" -ne 0 ]; then
    docker compose -f "${compose_file}" logs || true
  fi
  docker compose -f "${compose_file}" down -t 0 || true
}
trap cleanup EXIT

mkdir -p "tests/logs/${modsec_version}"
docker compose -f "${compose_file}" up -d "${modsec_version}"
sleep 10
docker compose -f "${compose_file}" logs
if ! [ "$(docker inspect "${modsec_version}" --format='{{.State.Running}}')" = "true" ]; then
  echo "Web server failed to start. Aborting."
  exit 1
fi

./ftw check -d tests/regression/tests
./ftw run \
  -d tests/regression/tests \
  --log-file "tests/logs/${modsec_version}/error.log" \
  --overrides "tests/regression/${backend}-overrides.yaml" \
  --show-failures-only
