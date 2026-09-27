#!/usr/bin/env bash
# Verifies the behaviour of a running container: that the rules block an attack,
# that a blocked request carries the configured CORS headers, how HTTP/2 is
# negotiated and whether HTTP/3 is advertised.
#
# The container has to be running already; this script only talks to it over HTTP.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tests/verify-image.sh --variant <nginx|apache> [options]

Options:
  --variant NAME         Image variant under test. The CORS and Alt-Svc checks
                         only apply to nginx.
  --url URL              Plain HTTP base URL (default http://localhost:8080).
  --tls-url URL          HTTPS base URL (default https://localhost:8443).
  --expect-h3-port PORT  Require Alt-Svc to advertise h3 on PORT. Without it the
                         Alt-Svc header has to be absent, which is the default
                         configuration.
  --timeout SECONDS      How long to wait for the container to answer
                         (default 60).
EOF
}

variant=""
url="http://localhost:8080"
tls_url="https://localhost:8443"
expect_h3_port=""
timeout=60

# need_value <option> <remaining args>: an option that takes a value has to have one
need_value() {
  if [ "${2}" -lt 2 ]; then
    printf 'Missing value for %s\n\n' "${1}" >&2
    usage >&2
    exit 2
  fi
}

while [ ${#} -gt 0 ]; do
  case "${1}" in
  --variant)
    need_value "${1}" "${#}"
    variant="${2}"
    shift 2
    ;;
  --url)
    need_value "${1}" "${#}"
    url="${2}"
    shift 2
    ;;
  --tls-url)
    need_value "${1}" "${#}"
    tls_url="${2}"
    shift 2
    ;;
  --expect-h3-port)
    need_value "${1}" "${#}"
    expect_h3_port="${2}"
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

case "${variant}" in
nginx | apache) ;;
"")
  printf -- '--variant is required\n\n' >&2
  usage >&2
  exit 2
  ;;
*)
  printf 'Unknown variant: %s (expected nginx or apache)\n' "${variant}" >&2
  exit 2
  ;;
esac

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

# header <name> <file>: the value of a response header, without the trailing CR.
# Empty when the header was not sent, which then shows up as the actual value.
header() {
  { grep -i "^${1}:" "${2}" || true; } | head -1 | cut -d: -f2- | sed 's/^ *//; s/\r$//'
}

# status <file>: the status code of the first response line
status() {
  awk 'NR == 1 { print $2 }' "${1}"
}

# present <name> <file>: whether a response header was sent at all
present() {
  if grep -qi "^${1}:" "${2}"; then echo "yes"; else echo "no"; fi
}

# contains <pattern> <text>: whether curl's trace holds a line matching pattern
contains() {
  if grep -qiE "${1}" <<<"${2}"; then echo "yes"; else echo "no"; fi
}

wait_for_container() {
  local deadline=$((SECONDS + timeout))
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    if curl -sS --connect-timeout 5 --max-time 5 -o /dev/null "${url}" 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  printf 'Container did not answer on %s within %s seconds\n' "${url}" "${timeout}" >&2
  return 1
}

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

wait_for_container

printf '\n### %s: blocked request ###\n' "${variant}"

attack_headers="${workdir}/attack.txt"
curl -sS -D "${attack_headers}" -o /dev/null "${url}/?test=../../etc/passwd"
check "attack request is blocked" "403" "$(status "${attack_headers}")"

if [ "${variant}" = "nginx" ]; then
  check "403 Content-Type" "text/html" "$(header content-type "${attack_headers}")"
  check "403 Access-Control-Allow-Origin" "*" "$(header access-control-allow-origin "${attack_headers}")"
  check "403 Access-Control-Max-Age" "3600" "$(header access-control-max-age "${attack_headers}")"
  check "403 Access-Control-Allow-Methods" "GET, POST, PUT, DELETE, OPTIONS" \
    "$(header access-control-allow-methods "${attack_headers}")"
  check "403 Access-Control-Allow-Headers" "*" "$(header access-control-allow-headers "${attack_headers}")"

  printf '\n### %s: HTTP/3 advertisement ###\n' "${variant}"

  tls_headers="${workdir}/tls.txt"
  curl -sS -k -D "${tls_headers}" -o /dev/null "${tls_url}/"
  if [ -n "${expect_h3_port}" ]; then
    check "Alt-Svc advertises h3 on port ${expect_h3_port}" "yes" \
      "$(grep -qi "^alt-svc:.*h3=\":${expect_h3_port}\"" "${tls_headers}" && echo yes || echo no)"
  else
    check "no Alt-Svc header with HTTP3 unset" "no" "$(present alt-svc "${tls_headers}")"
  fi
fi

printf '\n### %s: HTTP/2 ###\n' "${variant}"

upgrade="$(curl -sv --http2 -o /dev/null "${url}" 2>&1 || true)"
if [ "${variant}" = "apache" ]; then
  check "h2c upgrade is accepted" "yes" "$(contains '101 Switching Protocols' "${upgrade}")"
  check "the upgraded response is HTTP/2" "yes" "$(contains '< HTTP/2' "${upgrade}")"
else
  # nginx dropped the Upgrade: h2c mechanism in 1.25.1, leaving prior knowledge
  # as the only way to reach HTTP/2 without TLS.
  check "h2c upgrade is not offered" "no" "$(contains '101 Switching Protocols' "${upgrade}")"
fi

prior="$(curl -sv --http2-prior-knowledge -o /dev/null "${url}" 2>&1 || true)"
check "HTTP/2 prior knowledge is served" "yes" "$(contains '< HTTP/2' "${prior}")"
check "HTTP/2 prior knowledge does not upgrade" "no" \
  "$(contains '101 Switching Protocols' "${prior}")"

printf '\n'
if [ "${failed}" -ne 0 ]; then
  printf 'Some checks failed.\n' >&2
  exit 1
fi
printf 'All checks passed.\n'
