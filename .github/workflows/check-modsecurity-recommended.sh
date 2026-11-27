#!/usr/bin/env bash
# Checks that the upstream modsecurity.conf-recommended still has the hash that
# src/etc/modsecurity.d/modsecurity.conf was derived from, so that changes
# upstream get noticed.
#
# The expected hash is in modsecurity.conf-recommended.sha256 next to this
# script, in sha256sum format: <hash><space><format (space for text)><file name>.
# MODSECURITY_RECOMMENDED overrides it with such a line.
set -euo pipefail

: "${MODSECURITY_RECOMMENDED:=$(cat "$(dirname "${0}")/modsecurity.conf-recommended.sha256")}"

# sha256sum only warns about a line it cannot parse and still succeeds, which
# would let a mistyped hash pass, so insist on the exact format first
if ! grep -Eq '^[0-9a-f]{64}  modsecurity\.conf-recommended$' <<<"${MODSECURITY_RECOMMENDED}"; then
  echo "MODSECURITY_RECOMMENDED is not '<sha256 hash>  modsecurity.conf-recommended': ${MODSECURITY_RECOMMENDED}" >&2
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT
cd "${workdir}"

curl -sSL https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended -o modsecurity.conf-recommended
echo "${MODSECURITY_RECOMMENDED}" >sha256sum.txt
if command -v sha256sum >/dev/null; then
  sha256sum -c sha256sum.txt
else
  # macOS ships shasum instead
  shasum -a 256 -c sha256sum.txt
fi
