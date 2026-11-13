#!/usr/bin/env bash
# Verifies server-side mutual TLS of running containers:
# - client certificate acceptance, missing/untrusted/revoked certificate
#   rejection, HTTP -> HTTPS 301 redirect, and CRS request filtering
# - client identity header forwarding (${SSL_CLIENT_HEADER_PREFIX}Client-DN and
#   ${SSL_CLIENT_HEADER_PREFIX}Client-Verify), custom header prefixes, and
#   protection against client-supplied forged headers
# - fail-loud startup refusal when SSL_CLIENT_CA_CERT_FILE is missing
# - optional_no_ca mode accepting unverified client certificates without
#   forwarding their claimed subject DN
#
# When invoked without arguments after `./tests/setup-mtls.sh <target>` and
# `docker compose -f tests/docker-compose.mtls.yml up -d`, it runs all checks
# against the compose services. Individual options can also be passed to test a
# single container.
set -euo pipefail

# usage: print the available options
usage() {
  cat <<'EOF'
Usage: tests/verify-mtls.sh [options]

Options:
  --url URL                HTTPS base URL (default https://localhost:8444 in
                           compose mode, https://localhost:8443 otherwise).
  --http-url URL           Plain HTTP base URL used to verify the 301 HTTPS
                           redirect when mTLS is enabled.
  --client-cert FILE       Client certificate signed by the configured CA.
  --client-key FILE        Private key of the client certificate.
  --rejected-cert FILE     Client certificate that has to be rejected (e.g. one
                           revoked through SSL_CLIENT_CA_REVOCATION_FILE).
  --rejected-key FILE      Private key of the rejected certificate.
  --selfsigned-cert FILE   Self-signed client certificate not trusted by the CA.
  --selfsigned-key FILE    Private key of the self-signed certificate.
  --expect-dn TEXT         Assert that the backend receives Client-DN
                           containing TEXT. Requires the albedo test backend,
                           which logs the request headers it receives.
  --backend-container NAME Container running the albedo test backend used to
                           verify the forwarded headers (default: mtls-backend).
  --header-prefix PREFIX   Header prefix expected on the primary container
                           (default X-SSL-).
  --noca-container NAME    Container started without CA certificates that must
                           refuse to start.
  --unverified-url URL     HTTPS base URL of an optional_no_ca container.
  --revoked-url URL        HTTPS base URL of a CRL-enabled container.
  --revoked-prefix PREFIX  Header prefix expected on the CRL container
                           (default X-TLS-).
  --off-url URL            HTTPS base URL of a container with client
                           certificate verification disabled (default
                           https://localhost:8447 in compose mode).
  --off-http-url URL       Plain HTTP base URL of that container (default
                           http://localhost:8094 in compose mode).
  --redirect-port PORT     Expected port in the HTTP -> HTTPS redirect
                           (default 8444 in compose mode; any port when unset).
  --bad-depth-container NAME
                           Container started with an invalid SSL_VERIFY_DEPTH
                           that must refuse to start.
  --timeout SECONDS        How long to wait for a container to answer
                           (default 60).
EOF
}

script_dir="$(cd "$(dirname "${0}")" && pwd)"
certs_dir="${script_dir}/mtls-certs"

url=""
http_url=""
client_cert=""
client_key=""
rejected_cert=""
rejected_key=""
selfsigned_cert=""
selfsigned_key=""
expect_dn=""
header_prefix="X-SSL-"
backend_container="mtls-backend"
noca_container=""
unverified_url=""
revoked_url=""
revoked_prefix="X-TLS-"
off_url=""
off_http_url=""
redirect_port=""
bad_depth_container=""
timeout=60

# need_value <option> <remaining args>: the option takes a value if there is one
need_value() {
  if [ "${2}" -lt 2 ]; then
    printf 'Missing value for %s\n\n' "${1}" >&2
    usage >&2
    exit 2
  fi
}

while [ ${#} -gt 0 ]; do
  case "${1}" in
  --url)
    need_value "${1}" "${#}"
    url="${2}"
    shift 2
    ;;
  --http-url)
    need_value "${1}" "${#}"
    http_url="${2}"
    shift 2
    ;;
  --client-cert)
    need_value "${1}" "${#}"
    client_cert="${2}"
    shift 2
    ;;
  --client-key)
    need_value "${1}" "${#}"
    client_key="${2}"
    shift 2
    ;;
  --rejected-cert)
    need_value "${1}" "${#}"
    rejected_cert="${2}"
    shift 2
    ;;
  --rejected-key)
    need_value "${1}" "${#}"
    rejected_key="${2}"
    shift 2
    ;;
  --selfsigned-cert)
    need_value "${1}" "${#}"
    selfsigned_cert="${2}"
    shift 2
    ;;
  --selfsigned-key)
    need_value "${1}" "${#}"
    selfsigned_key="${2}"
    shift 2
    ;;
  --expect-dn)
    need_value "${1}" "${#}"
    expect_dn="${2}"
    shift 2
    ;;
  --header-prefix)
    need_value "${1}" "${#}"
    header_prefix="${2}"
    shift 2
    ;;
  --backend-container)
    need_value "${1}" "${#}"
    backend_container="${2}"
    shift 2
    ;;
  --noca-container)
    need_value "${1}" "${#}"
    noca_container="${2}"
    shift 2
    ;;
  --unverified-url)
    need_value "${1}" "${#}"
    unverified_url="${2}"
    shift 2
    ;;
  --revoked-url)
    need_value "${1}" "${#}"
    revoked_url="${2}"
    shift 2
    ;;
  --revoked-prefix)
    need_value "${1}" "${#}"
    revoked_prefix="${2}"
    shift 2
    ;;
  --off-url)
    need_value "${1}" "${#}"
    off_url="${2}"
    shift 2
    ;;
  --off-http-url)
    need_value "${1}" "${#}"
    off_http_url="${2}"
    shift 2
    ;;
  --redirect-port)
    need_value "${1}" "${#}"
    redirect_port="${2}"
    shift 2
    ;;
  --bad-depth-container)
    need_value "${1}" "${#}"
    bad_depth_container="${2}"
    shift 2
    ;;
  --timeout)
    need_value "${1}" "${#}"
    timeout="${2}"
    shift 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    printf 'Unknown option: %s\n\n' "${1}" >&2
    usage >&2
    exit 2
    ;;
  esac
done

# Default to the compose setup produced by tests/setup-mtls.sh and
# tests/docker-compose.mtls.yml when no certificate flags were given.
if [ -z "${client_cert}" ] && [ -z "${client_key}" ] && [ -f "${certs_dir}/client.crt" ]; then
  url="${url:-https://localhost:8444}"
  http_url="${http_url:-http://localhost:8091}"
  client_cert="${certs_dir}/client.crt"
  client_key="${certs_dir}/client.key"
  rejected_cert="${rejected_cert:-${certs_dir}/rejected.crt}"
  rejected_key="${rejected_key:-${certs_dir}/rejected.key}"
  selfsigned_cert="${selfsigned_cert:-${certs_dir}/selfsigned.crt}"
  selfsigned_key="${selfsigned_key:-${certs_dir}/selfsigned.key}"
  expect_dn="${expect_dn:-CN=mtls-client}"
  noca_container="${noca_container:-mtls-noca-test}"
  unverified_url="${unverified_url:-https://localhost:8445}"
  revoked_url="${revoked_url:-https://localhost:8446}"
  off_url="${off_url:-https://localhost:8447}"
  off_http_url="${off_http_url:-http://localhost:8094}"
  redirect_port="${redirect_port:-8444}"
  bad_depth_container="${bad_depth_container:-mtls-bad-depth-test}"
fi

url="${url:-https://localhost:8443}"

if [ -z "${client_cert}" ] || [ -z "${client_key}" ]; then
  printf -- '--client-cert and --client-key are required (or run tests/setup-mtls.sh first)\n\n' >&2
  usage >&2
  exit 2
fi

failed=0

# check <name> <expected> <actual>
check() {
  if [ "${3}" = "${2}" ]; then
    printf 'ok   %s\n' "${1}"
  else
    printf 'FAIL %s\n       expected: %s\n       actual:   %s\n' "${1}" "${2}" "${3}"
    failed=1
  fi
}

# status <file>: the status code of the first response line
status() {
  awk 'NR == 1 { print $2 }' "${1}"
}

# request_url <target_url> <curl args...>: outcome of a benign request against
# target_url. Returns the HTTP status code of the response, "rejected" when the
# TLS handshake or the request was turned away (httpd fails the handshake
# outright, while nginx completes the TLS 1.3 handshake and answers with 400),
# or "error-<curl exit status>" when the request failed for another reason.
# Only a TLS alert (for example "alert certificate required", "alert unknown
# ca" or "alert certificate revoked") counts as a rejection, so a missing
# certificate file, an unreachable container or a timeout fails the check
# instead of passing as an expected rejection.
request_url() {
  local target_url="${1}"
  shift
  local code rc=0 err="${workdir}/curl.err"
  code="$(curl -skS --connect-timeout 5 --max-time 10 -o /dev/null \
    -w '%{http_code}' "$@" "${target_url}/" 2>"${err}")" || rc=$?
  if [ "${rc}" -ne 0 ]; then
    if grep -qi 'alert' "${err}"; then
      echo "rejected"
      return 0
    fi
    printf 'request to %s failed unexpectedly (curl exit status %s):\n' \
      "${target_url}" "${rc}" >&2
    sed 's/^/  /' "${err}" >&2
    echo "error-${rc}"
    return 0
  fi
  if [ "${code}" = "400" ]; then
    echo "rejected"
  else
    echo "${code}"
  fi
}

# request <curl args...>: outcome of a benign request against the primary URL
request() {
  request_url "${url}" "$@"
}

# backend_lines: number of log lines the albedo test backend has emitted so far
backend_lines() {
  docker logs "${backend_container}" 2>&1 | wc -l
}

# inspect <target_url> <curl args...>: request the albedo test backend's
# /inspect endpoint through the proxy and print the backend log lines that the
# request produced. Albedo logs the headers it receives there, which is how the
# forwarded client identity is verified.
inspect() {
  local target_url="${1}"
  shift
  local before delta=""
  before="$(backend_lines)"
  curl -sk --connect-timeout 5 --max-time 10 -o /dev/null "$@" "${target_url}/inspect"
  local attempt
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    delta="$(docker logs "${backend_container}" 2>&1 | tail -n +$((before + 1)))"
    if grep -qi "inspection request" <<< "${delta}"; then
      break
    fi
    sleep 0.2
  done
  printf '%s\n' "${delta}"
}

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

if [ -z "${selfsigned_cert}" ] || [ -z "${selfsigned_key}" ]; then
  selfsigned_cert="${workdir}/untrusted.crt"
  selfsigned_key="${workdir}/untrusted.key"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "${selfsigned_key}" -out "${selfsigned_cert}" \
    -subj "/CN=untrusted" 2>/dev/null
fi

# wait_for_url <target_url> <curl args...>: wait until the container at
# target_url answers
wait_for_url() {
  local target_url="${1}"
  shift
  # SECONDS is a bash built-in variable that automatically increments by 1 each
  # second since the shell started.
  local deadline=$((SECONDS + timeout))
  local outcome
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    outcome="$(request_url "${target_url}" "$@" 2>/dev/null)"
    case "${outcome}" in
      rejected | error-*) ;;
      *) return 0 ;;
    esac
    sleep 2
  done
  printf 'Container did not answer within %s seconds\n' "${timeout}" >&2
  return 1
}

# wait_for_container <target_url> <cert> <key>: wait until the container at
# target_url accepts the given client certificate
wait_for_container() {
  wait_for_url "${1}" --cert "${2}" --key "${3}"
}

# wait_for_exit <container>: wait until the container stops, for at most
# $timeout seconds; the following checks report whether it actually stopped
wait_for_exit() {
  local container="${1}"
  local deadline=$((SECONDS + timeout))
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    if [ "$(docker inspect -f '{{.State.Running}}' "${container}")" = "false" ]; then
      break
    fi
    sleep 1
  done
}

wait_for_container "${url}" "${client_cert}" "${client_key}"

printf '\n### mutual TLS: client certificates ###\n'

check "client certificate is accepted" "200" \
  "$(request --cert "${client_cert}" --key "${client_key}")"
check "missing client certificate is rejected" "rejected" "$(request)"
check "untrusted client certificate is rejected" "rejected" \
  "$(request --cert "${selfsigned_cert}" --key "${selfsigned_key}")"
if [ -n "${rejected_cert}" ] && [ -z "${revoked_url}" ]; then
  check "rejected client certificate is refused" "rejected" \
    "$(request --cert "${rejected_cert}" --key "${rejected_key}")"
fi

if [ -n "${http_url}" ]; then
  http_headers="${workdir}/http-redirect.txt"
  curl -sS -D "${http_headers}" -o /dev/null \
    -H "${header_prefix}Client-DN: CN=forged-dn" \
    -H "${header_prefix}Client-Verify: forged-verify" \
    "${http_url}/"
  check "plain HTTP request redirects to HTTPS with 301" "301" \
    "$(status "${http_headers}")"
  if [ -n "${redirect_port}" ]; then
    check "plain HTTP redirect uses the configured redirect port" "yes" \
      "$(grep -qiE "^location: https://[^/]*:${redirect_port}/" "${http_headers}" && echo yes || echo no)"
  else
    check "plain HTTP redirect includes the HTTPS port" "yes" \
      "$(grep -qiE '^location: https://[^/]*:[0-9]+/' "${http_headers}" && echo yes || echo no)"
  fi
fi

printf '\n### mutual TLS: request filtering ###\n'

attack_headers="${workdir}/attack.txt"
curl -sk -D "${attack_headers}" -o /dev/null \
  --cert "${client_cert}" --key "${client_key}" "${url}/?test=../../etc/passwd"
check "attack request is blocked" "403" "$(status "${attack_headers}")"

# check_identity <target_url> <prefix>: verify through the albedo test backend
# log that the backend receives the expected client DN and verification status
# under <prefix>, and that client-supplied forged headers with that prefix are
# replaced.
check_identity() {
  local target_url="${1}"
  local prefix="${2}"
  local dn_header="${prefix}Client-DN"
  local verify_header="${prefix}Client-Verify"
  local delta

  delta="$(inspect "${target_url}" --cert "${client_cert}" --key "${client_key}")"
  check "backend receives ${dn_header}" "yes" \
    "$(grep -iF "request.headers.${dn_header}=" <<< "${delta}" | grep -qF "${expect_dn}" && echo yes || echo no)"
  check "backend receives ${verify_header}" "yes" \
    "$(grep -iF "request.headers.${verify_header}=" <<< "${delta}" | grep -qi "success" && echo yes || echo no)"

  delta="$(inspect "${target_url}" --cert "${client_cert}" --key "${client_key}" \
    -H "${dn_header}: CN=forged-dn" -H "${verify_header}: forged-verify")"
  check "forged ${prefix}Client-* headers are replaced" "yes" \
    "$(grep -iF "request.headers.${dn_header}=" <<< "${delta}" | grep -qF "${expect_dn}" \
      && ! grep -qiF "forged" <<< "${delta}" && echo yes || echo no)"
}

if [ -n "${expect_dn}" ]; then
  printf '\n### mutual TLS: client identity ###\n'
  check_identity "${url}" "${header_prefix}"
fi

if [ -n "${off_url}" ]; then
  printf '\n### mutual TLS: verification disabled ###\n'

  wait_for_url "${off_url}"

  if [ -n "${off_http_url}" ]; then
    check "plain HTTP request is proxied when verification is disabled" "200" \
      "$(request_url "${off_http_url}")"
  fi

  # With client certificate verification disabled the proxy must not touch the
  # identity headers, so deployments behind their own mTLS proxy keep working.
  delta="$(inspect "${off_url}" \
    -H "${header_prefix}Client-DN: CN=off-dn" \
    -H "${header_prefix}Client-Verify: SUCCESS")"
  check "client-supplied identity headers pass through when verification is disabled" "yes" \
    "$(grep -qiF "request.headers.${header_prefix}Client-DN=" <<< "${delta}" \
      && grep -qiF "CN=off-dn" <<< "${delta}" && echo yes || echo no)"
fi

if [ -n "${noca_container}" ]; then
  printf '\n### mutual TLS: missing CA refusal ###\n'

  wait_for_exit "${noca_container}"
  check "container without CA certificates stops" "false" \
    "$(docker inspect -f '{{.State.Running}}' "${noca_container}")"
  check "container without CA certificates exits non-zero" "yes" \
    "$([ "$(docker inspect -f '{{.State.ExitCode}}' "${noca_container}")" != "0" ] && echo yes || echo no)"
  check "container logs missing CA error" "yes" \
    "$(docker logs "${noca_container}" 2>&1 | grep -q "requires SSL_CLIENT_CA_CERT_FILE" && echo yes || echo no)"
fi

if [ -n "${bad_depth_container}" ]; then
  printf '\n### mutual TLS: invalid verification depth refusal ###\n'

  wait_for_exit "${bad_depth_container}"
  check "container with an invalid SSL_VERIFY_DEPTH stops" "false" \
    "$(docker inspect -f '{{.State.Running}}' "${bad_depth_container}")"
  check "container with an invalid SSL_VERIFY_DEPTH exits non-zero" "yes" \
    "$([ "$(docker inspect -f '{{.State.ExitCode}}' "${bad_depth_container}")" != "0" ] && echo yes || echo no)"
  check "container logs invalid SSL_VERIFY_DEPTH error" "yes" \
    "$(docker logs "${bad_depth_container}" 2>&1 | grep -q "invalid SSL_VERIFY_DEPTH" && echo yes || echo no)"
fi

if [ -n "${unverified_url}" ]; then
  printf '\n### mutual TLS: unverified client certificates (optional_no_ca) ###\n'

  wait_for_container "${unverified_url}" "${selfsigned_cert}" "${selfsigned_key}"

  check "self-signed client certificate is accepted under optional_no_ca" "200" \
    "$(request_url "${unverified_url}" --cert "${selfsigned_cert}" --key "${selfsigned_key}")"

  delta="$(inspect "${unverified_url}" --cert "${selfsigned_cert}" --key "${selfsigned_key}")"
  check "unverified certificate request reaches the backend" "yes" \
    "$(grep -qi "inspection request" <<< "${delta}" && echo yes || echo no)"
  check "claimed DN of unverified certificate is not forwarded" "no" \
    "$(grep -qiF "request.headers.${header_prefix}Client-DN=" <<< "${delta}" && echo yes || echo no)"
  check "verification result of unverified certificate is forwarded" "yes" \
    "$(grep -qiF "request.headers.${header_prefix}Client-Verify=" <<< "${delta}" && echo yes || echo no)"

  # Under permissive modes (optional / optional_no_ca), a TLS request without a
  # client certificate is allowed and proxied to the backend. Verify that
  # client-supplied identity headers are stripped when no certificate was
  # presented, so an unauthenticated client cannot forge an identity.
  delta="$(inspect "${unverified_url}" \
    -H "${header_prefix}Client-DN: CN=forged-dn" \
    -H "${header_prefix}Client-Verify: forged-verify")"
  check "no-certificate request reaches the backend under optional_no_ca" "yes" \
    "$(grep -qi "inspection request" <<< "${delta}" && echo yes || echo no)"
  check "forged identity headers are not forwarded without a certificate" "no" \
    "$(grep -qiF "forged" <<< "${delta}" && echo yes || echo no)"
fi

if [ -n "${revoked_url}" ] && [ -n "${rejected_cert}" ]; then
  printf '\n### mutual TLS: CRL revocation and custom header prefix ###\n'

  wait_for_container "${revoked_url}" "${client_cert}" "${client_key}"

  check "non-revoked client certificate is accepted" "200" \
    "$(request_url "${revoked_url}" --cert "${client_cert}" --key "${client_key}")"
  check "revoked client certificate is refused" "rejected" \
    "$(request_url "${revoked_url}" --cert "${rejected_cert}" --key "${rejected_key}")"
  if [ -n "${expect_dn}" ]; then
    check_identity "${revoked_url}" "${revoked_prefix}"
  fi
fi

printf '\n'
if [ "${failed}" -ne 0 ]; then
  printf 'Some checks failed.\n' >&2
  exit 1
fi
printf 'All checks passed.\n'
