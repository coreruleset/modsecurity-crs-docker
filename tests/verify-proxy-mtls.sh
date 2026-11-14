#!/usr/bin/env bash
# Verifies mutual TLS from the proxy to its backend: with PROXY_SSL=on the
# container has to present the client certificate in PROXY_SSL_CERT_FILE and
# PROXY_SSL_CERT_KEY_FILE to a backend that insists on one, and has to refuse to
# start when the configured files do not exist.
#
# Starts its own containers and network, and removes them and the generated
# certificates afterwards. On failure their logs are printed first.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tests/verify-proxy-mtls.sh <target>

  target  Build target, e.g. nginx-debian-writable-latest or apache-debian-latest.
          The image <target>-verification has to exist locally.
EOF
}

target="${1:-${TARGET:-}}"
if [ -z "${target}" ]; then
  usage >&2
  exit 2
fi

cd "$(dirname "${0}")/.."

variant="apache"
cert_dir="/usr/local/apache2/conf"
if [[ "${target}" == *nginx* ]]; then
  variant="nginx"
  cert_dir="/etc/nginx/conf"
fi

image="${target}-verification"
# Unique per invocation: the server-side mTLS stack in tests/docker-compose.mtls.yml
# also has an mtls-backend, and cleanup must only ever remove what this script made
network="proxy-mtls-net-$$"
backend="proxy-mtls-backend-$$"
proxy="${target}-proxy-mtls-test-$$"
missing="${target}-proxy-mtls-missing-test-$$"

workdir="$(mktemp -d)"
# The containers read the files through bind mounts
chmod 755 "${workdir}"
./tests/write-target-env.sh "${target}" "${workdir}/target.env"

# cleanup: on failure, show what the containers logged, then remove everything
# this script created
cleanup() {
  local status=$?
  if [ "${status}" -ne 0 ]; then
    docker logs "${proxy}" >&2 || true
    docker logs "${missing}" >&2 || true
    docker logs "${backend}" >&2 || true
  fi
  docker rm -f "${proxy}" "${missing}" "${backend}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  rm -rf "${workdir}"
}
trap cleanup EXIT

# fail <message>
fail() {
  printf 'FAIL %s\n' "${1}" >&2
  exit 1
}

# Client certificate signed by the test CA. Apache expects only the leaf
# certificate in PROXY_SSL_CERT_FILE (see the README), so the same files work for
# both variants.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${workdir}/ca.key" -out "${workdir}/ca.crt" -days 1 -subj "/CN=test-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey rsa:2048 -nodes \
  -keyout "${workdir}/proxy.key" -out "${workdir}/proxy.csr" -subj "/CN=proxy"
openssl x509 -req -in "${workdir}/proxy.csr" -CA "${workdir}/ca.crt" -CAkey "${workdir}/ca.key" \
  -CAcreateserial -days 1 -out "${workdir}/proxy.crt"
# Strip the trailing newline from the certificate to verify PEM concatenation
# (command substitution drops it)
printf '%s' "$(cat "${workdir}/proxy.crt")" >"${workdir}/proxy-no-nl.crt"
mv "${workdir}/proxy-no-nl.crt" "${workdir}/proxy.crt"
chmod 644 "${workdir}/proxy.crt" "${workdir}/proxy.key"

# Self-signed server certificate for the backend; the WAF does not verify the
# backend certificate (PROXY_SSL_VERIFY stays at its default).
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${workdir}/backend.key" -out "${workdir}/backend.crt" -days 1 -subj "/CN=backend"
chmod 644 "${workdir}/backend.crt" "${workdir}/backend.key"

# Backend that aborts the TLS handshake unless the client presents a certificate
# chaining up to ca.crt. An allowed request returning the s_server page below
# therefore proves that the client certificate was presented and accepted.
docker network create "${network}"
docker run \
  --pull "never" \
  -d \
  --name "${backend}" \
  --network "${network}" \
  -v "${workdir}/backend.crt:/tls/backend.crt:ro" \
  -v "${workdir}/backend.key:/tls/backend.key:ro" \
  -v "${workdir}/ca.crt:/tls/ca.crt:ro" \
  -p 9443:9443 \
  --entrypoint openssl \
  "${image}" \
  s_server -accept 9443 -cert /tls/backend.crt -key /tls/backend.key \
  -Verify 1 -CAfile /tls/ca.crt -www

echo "Starting container ${proxy} with PROXY_SSL=on"
docker run \
  --pull "never" \
  -d \
  --name "${proxy}" \
  --network "${network}" \
  --env-file "${workdir}/target.env" \
  -e "BACKEND=https://${backend}:9443" \
  -e PROXY_SSL=on \
  -v "${workdir}/proxy.crt:${cert_dir}/proxy.crt:ro" \
  -v "${workdir}/proxy.key:${cert_dir}/proxy.key:ro" \
  -p 8081:8080 \
  -p 8444:8443 \
  "${image}"

./tests/verify-image.sh \
  --variant "${variant}" \
  --url http://localhost:8081 \
  --tls-url https://localhost:8444

# The output is captured first: grep -q can close a pipe early, which pipefail
# turns into a failure
proxy_logs="$(docker logs "${proxy}" 2>&1)"
grep -q "using proxy client certificate" <<<"${proxy_logs}" ||
  fail "the container did not report using the proxy client certificate"

# An allowed request has to reach the mTLS backend and come back with its page
page="$(curl -sS --fail --retry 8 --retry-delay 2 --retry-all-errors http://localhost:8081/)"
grep -q "s_server" <<<"${page}" ||
  fail "the request did not come back with the mTLS backend's page"

# Negative control: the backend rejects connections without a client certificate
if curl -sk --max-time 5 https://localhost:9443/ >/dev/null 2>&1; then
  fail "the mTLS backend accepted a connection without a client certificate"
fi

# A configured path that does not hold both files has to stop the container
docker run \
  --pull "never" \
  -d \
  --name "${missing}" \
  --env-file "${workdir}/target.env" \
  -e PROXY_SSL=on \
  -e PROXY_SSL_CERT_FILE=/nonexistent/proxy.crt \
  -e PROXY_SSL_CERT_KEY_FILE=/nonexistent/proxy.key \
  "${image}"
sleep 5
[ "$(docker inspect -f '{{.State.Running}}' "${missing}")" = "false" ] ||
  fail "the container with missing certificate files is still running"
[ "$(docker inspect -f '{{.State.ExitCode}}' "${missing}")" != "0" ] ||
  fail "the container with missing certificate files exited with status 0"
missing_logs="$(docker logs "${missing}" 2>&1)"
grep -q "does not point to both existing files" <<<"${missing_logs}" ||
  fail "the container with missing certificate files did not say why it stopped"

printf 'All checks passed.\n'
