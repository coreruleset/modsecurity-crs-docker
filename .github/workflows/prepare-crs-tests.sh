#!/usr/bin/env bash
# Points the compose file of the CRS checkout in ./crs at the image built for a
# target, so that its regression tests run against that image. Safe to run again
# for another target.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: .github/workflows/prepare-crs-tests.sh <target>

  target  Build target, e.g. nginx-debian-writable-latest. The CRS checkout has
          to be in ./crs of the repository root.
EOF
}

target="${1:-${TARGET:-}}"
if [ -z "${target}" ]; then
  usage >&2
  exit 2
fi

cd "$(dirname "${0}")/../.."

flavor="nginx"
if [[ "${target}" == *apache* ]]; then
  flavor="apache"
fi

# Use the verification image instead of the published one, or the one an earlier
# run for another target put there
compose_file="crs/tests/docker-compose.yml"
sed -e "s#image: owasp/modsecurity-crs:${flavor}.*#image: ${target}-verification#" \
  -e "s#image: [^[:space:]]*-verification\$#image: ${target}-verification#" \
  "${compose_file}" >"${compose_file}.new"
mv "${compose_file}.new" "${compose_file}"
