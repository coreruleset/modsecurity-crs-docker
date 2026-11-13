#!/usr/bin/env bash
# Verifies the behaviour of a running container: that the rules block an attack,
# that a blocked request carries the configured CORS headers, how HTTP/2 is
# negotiated, whether HTTP/3 is advertised and, on request, how the TLS redirect
# treats ACME challenges.
#
# The container has to be running already, and this script only talks to it over
# HTTP, except for --tls-redirect-image: that test starts its own containers.
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
  --tls-redirect-image IMAGE
                         Instead of the checks above, test the always-TLS-redirect
                         option: start IMAGE (which has to exist locally) with the
                         option on, in front of an Albedo backend
                         (github.com/coreruleset/albedo), and require a redirect
                         to https for regular requests but none for ACME HTTP-01
                         challenges, which have to reach the backend unchanged.
                         The containers are removed afterwards; --url is ignored.
  --timeout SECONDS      How long to wait for the container to answer
                         (default 60).
EOF
}

variant=""
url="http://localhost:8080"
tls_url="https://localhost:8443"
expect_h3_port=""
tls_redirect_image=""
timeout=60

# Backend of the TLS redirect test
albedo_image="ghcr.io/coreruleset/albedo:0.3.0@sha256:843ed01d28f48b594dcc0278ea9403175a0bf40ec065432040b796f589e89507"

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
  --tls-redirect-image)
    need_value "${1}" "${#}"
    tls_redirect_image="${2}"
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

# wait_for_url <url> <what>: wait until something answers on url
wait_for_url() {
  local deadline=$((SECONDS + timeout))
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    if curl -sS --connect-timeout 5 --max-time 5 -o /dev/null "${1}" 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  printf '%s did not answer on %s within %s seconds\n' "${2}" "${1}" "${timeout}" >&2
  return 1
}

# Names of what the TLS redirect test starts; empty until then
redirect_network=""
redirect_backend=""
redirect_waf=""
albedo_url=""

# published_port <container>: the host port that container port 8080 is published on
published_port() {
  docker port "${1}" 8080/tcp | awk -F: 'NR == 1 { print $NF }'
}

# start_tls_redirect_containers: start Albedo and, in front of it, the image under
# test with the always-TLS-redirect option on, and point url and albedo_url at them.
# The rule engine is off so that the redirect, and not a CRS rule, decides the
# outcome for the paths under test.
start_tls_redirect_containers() {
  local redirect_var="APACHE_ALWAYS_TLS_REDIRECT"
  if [ "${variant}" = "nginx" ]; then
    redirect_var="NGINX_ALWAYS_TLS_REDIRECT"
  fi
  redirect_network="tls-redirect-net-$$"
  redirect_backend="tls-redirect-backend-$$"
  redirect_waf="tls-redirect-waf-$$"

  docker network create "${redirect_network}" >/dev/null
  docker run -d --name "${redirect_backend}" --network "${redirect_network}" \
    -p 127.0.0.1::8080 "${albedo_image}" >/dev/null
  docker run -d --pull never --name "${redirect_waf}" --network "${redirect_network}" \
    -p 127.0.0.1::8080 \
    -e MODSEC_RULE_ENGINE=off \
    -e "${redirect_var}=on" \
    -e "BACKEND=http://${redirect_backend}:8080" \
    "${tls_redirect_image}" >/dev/null

  albedo_url="http://127.0.0.1:$(published_port "${redirect_backend}")"
  url="http://127.0.0.1:$(published_port "${redirect_waf}")"
}

# cleanup: on failure, show what the TLS redirect test containers logged, then
# remove everything this script created
cleanup() {
  local status=$?
  if [ -n "${redirect_waf}" ]; then
    if [ "${status}" -ne 0 ]; then
      docker logs "${redirect_waf}" >&2 || true
      docker logs "${redirect_backend}" >&2 || true
    fi
    docker rm -f "${redirect_waf}" "${redirect_backend}" >/dev/null || true
    docker network rm "${redirect_network}" >/dev/null || true
  fi
  rm -rf "${workdir}"
}

workdir="$(mktemp -d)"
trap cleanup EXIT

if [ -n "${tls_redirect_image}" ]; then
  start_tls_redirect_containers
  wait_for_url "${albedo_url}" "Albedo"
fi
wait_for_url "${url}" "Container"

if [ -n "${tls_redirect_image}" ]; then
  printf '\n### %s: TLS redirect ###\n' "${variant}"

  redirect_headers="${workdir}/redirect.txt"
  curl -sS -D "${redirect_headers}" -o /dev/null "${url}/"
  check "regular request is redirected" "301" "$(status "${redirect_headers}")"
  check "regular request is redirected to https" "yes" \
    "$(grep -qi '^location: https://' "${redirect_headers}" && echo yes || echo no)"

  # Albedo answers the token URL with a known body, and only for exactly this path.
  # Getting that body back through the proxy shows that the challenge was forwarded
  # to the backend unchanged, and not redirected, answered by the proxy itself or
  # rewritten on the way.
  acme_path="/.well-known/acme-challenge/test-token"
  acme_token="test-token.thumbprint"
  curl -sS -o /dev/null -X POST -H 'Content-Type: application/json' \
    --data "{\"status\": 200, \"body\": \"${acme_token}\", \"endpoints\": [{\"method\": \"GET\", \"url\": \"${acme_path}\"}]}" \
    "${albedo_url}/configure_reflection"
  acme_body="${workdir}/acme-body.txt"
  curl -sS -D "${redirect_headers}" -o "${acme_body}" "${url}${acme_path}"
  check "ACME challenge is not redirected" "200" "$(status "${redirect_headers}")"
  check "ACME challenge is answered by the backend" "${acme_token}" "$(cat "${acme_body}")"

  # A path that only starts with the ACME prefix has to stay redirected once the
  # dot segments are resolved. --path-as-is keeps curl from resolving them first.
  # The Location has to be checked too: a backend can answer such a path with a
  # redirect of its own (Albedo does), which must not pass for the one to https.
  for dot_path in "/.well-known/acme-challenge/../../admin" "/.well-known/acme-challenge/%2e%2e/%2e%2e/admin"; do
    curl -sS --path-as-is -D "${redirect_headers}" -o /dev/null "${url}${dot_path}"
    check "${dot_path} is redirected" "301" "$(status "${redirect_headers}")"
    check "${dot_path} is redirected to https" "yes" \
      "$(grep -qi '^location: https://' "${redirect_headers}" && echo yes || echo no)"
  done

  # The remaining checks expect plain HTTP to be served, so they do not apply
  printf '\n'
  if [ "${failed}" -ne 0 ]; then
    printf 'Some checks failed.\n' >&2
    exit 1
  fi
  printf 'All checks passed.\n'
  exit 0
fi

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
