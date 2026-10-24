#!/usr/bin/env bash
# Verifies server-side mutual TLS of a running container: a client certificate
# signed by the configured CA is accepted and the request is still filtered by
# the CRS, while requests without a certificate, with an untrusted one or with
# a rejected one do not reach the backend.
#
# The container has to be running with SSL_VERIFY set and the CA certificates
# in SSL_CLIENT_CA_CERT_FILE, and with a backend that answers benign requests;
# this script only talks to it over HTTPS.
set -euo pipefail

# usage: print the available options
usage() {
  cat <<'EOF'
Usage: tests/verify-mtls.sh [options]

Options:
  --url URL              HTTPS base URL (default https://localhost:8443).
  --client-cert FILE     Client certificate signed by the configured CA.
  --client-key FILE      Private key of the client certificate.
  --rejected-cert FILE   Client certificate that has to be rejected (e.g. one
                         revoked through SSL_CLIENT_CA_REVOCATION_FILE).
  --rejected-key FILE    Private key of the rejected certificate.
  --expect-dn TEXT       Assert that the backend receives X-SSL-Client-DN
                         containing TEXT. Requires a backend that echoes its
                         request headers (see the workflow).
  --timeout SECONDS      How long to wait for the container to answer
                         (default 60).
EOF
}

url="https://localhost:8443"
client_cert=""
client_key=""
rejected_cert=""
rejected_key=""
expect_dn=""
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
  --expect-dn)
    need_value "${1}" "${#}"
    expect_dn="${2}"
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

if [ -z "${client_cert}" ] || [ -z "${client_key}" ]; then
  printf -- '--client-cert and --client-key are required\n\n' >&2
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

# request <curl args...>: outcome of a benign request. The HTTP status code of
# the response, or "rejected" when the TLS handshake or the request was turned
# away: httpd fails the handshake outright, while nginx completes the TLS 1.3
# handshake and answers the request with 400.
request() {
  local code
  if ! code="$(curl -sk --connect-timeout 5 --max-time 10 -o /dev/null \
    -w '%{http_code}' "$@" "${url}/" 2>/dev/null)"; then
    echo "rejected"
  elif [ "${code}" = "400" ]; then
    echo "rejected"
  else
    echo "${code}"
  fi
}

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

# a certificate the configured CA does not know
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "${workdir}/untrusted.key" -out "${workdir}/untrusted.crt" \
  -subj "/CN=untrusted" 2>/dev/null

# wait_for_container: wait until the container accepts the client certificate
wait_for_container() {
  local deadline=$((SECONDS + timeout))
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    if [ "$(request --cert "${client_cert}" --key "${client_key}")" != "rejected" ]; then
      return 0
    fi
    sleep 2
  done
  printf 'Container did not accept the client certificate within %s seconds\n' \
    "${timeout}" >&2
  return 1
}

wait_for_container

printf '\n### mutual TLS: client certificates ###\n'

check "client certificate is accepted" "200" \
  "$(request --cert "${client_cert}" --key "${client_key}")"
check "missing client certificate is rejected" "rejected" "$(request)"
check "untrusted client certificate is rejected" "rejected" \
  "$(request --cert "${workdir}/untrusted.crt" --key "${workdir}/untrusted.key")"
if [ -n "${rejected_cert}" ]; then
  check "rejected client certificate is refused" "rejected" \
    "$(request --cert "${rejected_cert}" --key "${rejected_key}")"
fi

printf '\n### mutual TLS: request filtering ###\n'

attack_headers="${workdir}/attack.txt"
curl -sk -D "${attack_headers}" -o /dev/null \
  --cert "${client_cert}" --key "${client_key}" "${url}/?test=../../etc/passwd"
check "attack request is blocked" "403" "$(status "${attack_headers}")"

if [ -n "${expect_dn}" ]; then
  printf '\n### mutual TLS: client identity ###\n'

  body="${workdir}/body.txt"
  curl -sk -o "${body}" --cert "${client_cert}" --key "${client_key}" "${url}/"
  check "backend receives X-SSL-Client-DN" "yes" \
    "$(grep -qiF "x-ssl-client-dn: ${expect_dn}" "${body}" && echo yes || echo no)"
  check "backend receives X-SSL-Client-Verify" "yes" \
    "$(grep -qiF "x-ssl-client-verify: success" "${body}" && echo yes || echo no)"

  # the identity headers must not be forgeable by the client
  curl -sk -o "${body}" --cert "${client_cert}" --key "${client_key}" \
    -H "X-SSL-Client-DN: CN=forged" -H "X-SSL-Client-Verify: SUCCESS" "${url}/"
  check "forged identity headers are replaced" "yes" \
    "$(grep -qiF "x-ssl-client-dn: ${expect_dn}" "${body}" && ! grep -qiF "cn=forged" "${body}" && echo yes || echo no)"
  if [ "$(request -H "X-SSL-Client-DN: CN=forged" -H "X-SSL-Client-Verify: SUCCESS")" != "rejected" ]; then
    curl -sk -o "${body}" -H "X-SSL-Client-DN: CN=forged" -H "X-SSL-Client-Verify: SUCCESS" "${url}/"
    check "forged identity headers are not forwarded without a certificate" "no" \
      "$(grep -qiF "cn=forged" "${body}" && echo yes || echo no)"
  fi
fi

printf '\n'
if [ "${failed}" -ne 0 ]; then
  printf 'Some checks failed.\n' >&2
  exit 1
fi
printf 'All checks passed.\n'
