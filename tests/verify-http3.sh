#!/usr/bin/env bash
# Verifies the HTTP/3 opt-in of the nginx images: with HTTP3=on the container
# has to advertise h3 on HTTP3_ALT_SVC_PORT. Starts its own container, so it
# does not need one running, and removes it afterwards.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tests/verify-http3.sh <target>

  target  An nginx build target, e.g. nginx-debian-writable-latest. The image
          <target>-verification has to exist locally.
EOF
}

target="${1:-${TARGET:-}}"
if [ -z "${target}" ]; then
  usage >&2
  exit 2
fi

cd "$(dirname "${0}")/.."

if [ "$(./tests/target-variant.sh "${target}")" != "nginx" ]; then
  printf 'HTTP/3 is only available in the nginx images, not in %s\n' "${target}" >&2
  exit 2
fi

# Unique per invocation, so that cleanup can only ever remove its own container.
# The suffix is random, as a PID can repeat, for example after an unclean exit.
suffix="$(mktemp -u XXXXXXXX)"
container="${target}-http3-test-${suffix}"
workdir="$(mktemp -d)"

# cleanup: on failure, show what the container logged, then remove it and the
# environment file
cleanup() {
  local status=$?
  if [ "${status}" -ne 0 ]; then
    docker logs "${container}" >&2 || true
  fi
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf "${workdir}"
}
trap cleanup EXIT

./tests/write-target-env.sh "${target}" "${workdir}/target.env"

echo "Starting container ${container} with HTTP3=on"
docker run \
  --pull "never" \
  -d \
  --name "${container}" \
  --env-file "${workdir}/target.env" \
  -e BACKEND=http://localhost:9999 \
  -e HTTP3=on \
  -e HTTP3_ALT_SVC_PORT=8444 \
  -p 8081:8080 \
  -p 8444:8443 \
  -p 8444:8443/udp \
  "${target}-verification"

./tests/verify-image.sh \
  --target "${target}" \
  --url http://localhost:8081 \
  --tls-url https://localhost:8444 \
  --expect-h3-port 8444
