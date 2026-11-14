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

cd "$(dirname "${0}")/../../crs"

modsec_version="modsec3-nginx"
backend="nginx"
if [[ "${target}" == *apache* ]]; then
  modsec_version="modsec2-apache"
  backend="httpd"
fi

mkdir -p "tests/logs/${modsec_version}"/{nginx,apache2}
docker compose -f ./tests/docker-compose.yml up -d "${modsec_version}"
sleep 10
docker compose -f ./tests/docker-compose.yml logs
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
