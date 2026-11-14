#!/usr/bin/env bash
# Adjusts the CRS checkout in ./crs so that its regression tests run against the
# image built for a target.
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

# Use the verification image instead of the published one
compose_file="crs/tests/docker-compose.yml"
sed "s#image: owasp/modsecurity-crs:${flavor}.*#image: ${target}-verification#" \
  "${compose_file}" >"${compose_file}.new"
mv "${compose_file}.new" "${compose_file}"

# nginx 1.30.0: 920100-4 now returns 405
yq e -i '(.test_overrides[] | select(.rule_id == 920100 and .test_ids[0] == 4 and (.test_ids | length) == 1) | .output.status) = 405' \
  crs/tests/regression/nginx-overrides.yaml

# Pin the CRS test container to a single nginx worker. go-ftw bounds the log
# output of a request with markers. Several workers flush their buffers
# independently, so lines interleave and tests such as 956100 fail at random
# (https://github.com/coreruleset/go-ftw/issues/473). This applies to the test
# setup only; the images still default to "auto".
yq e -i '.services.modsec3-nginx.environment.NGINX_WORKER_PROCESSES = "1"' \
  "${compose_file}"
