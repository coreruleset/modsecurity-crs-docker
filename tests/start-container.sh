#!/usr/bin/env bash
# Starts the image built for a target (tagged <target>-verification) with every
# configurable CRS variable set, and a dummy backend, for tests/verify-image.sh.
#
# The environment file only has to exist while the container is created, so it
# is written to a temporary directory and removed again.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tests/start-container.sh <target>

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

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

./tests/write-target-env.sh "${target}" "${workdir}/target.env"

# A container left over from an earlier run would keep the name and the ports
docker rm -f "${target}-test" >/dev/null 2>&1 || true

echo "Starting container ${target}-verification"
# The backend is a dummy
docker run \
  --pull "never" \
  -d \
  --name "${target}-test" \
  --env-file "${workdir}/target.env" \
  -p 8080:8080 \
  -p 8443:8443 \
  -e BACKEND=http://localhost:9999 \
  "${target}-verification"
