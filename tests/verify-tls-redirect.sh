#!/usr/bin/env bash
# Verifies how the TLS redirect treats ACME challenges, once for each way of
# turning the redirect on: the always-TLS-redirect option, and SSL_VERIFY, whose
# redirect has to exempt ACME challenges too. See tests/verify-image.sh
# --tls-redirect-image for what is checked.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tests/verify-tls-redirect.sh <target>

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

# The image ID pins the image that was just built, whatever the tag points at later
image_id="$(docker image inspect -f '{{.Id}}' "${target}-verification")"

for trigger in always ssl-verify; do
  printf '\n=== TLS redirect turned on by: %s ===\n' "${trigger}"
  ./tests/verify-image.sh \
    --target "${target}" \
    --tls-redirect-image "${image_id}" \
    --tls-redirect-trigger "${trigger}"
done
