#!/usr/bin/env bash
# Prints the image variant (nginx or apache) of a build target. This is the one
# rule the other scripts share: a target is nginx or apache, never both and never
# neither, so a mistyped target fails here instead of being tested as the wrong
# variant.
set -euo pipefail

usage() {
  cat <<'EOF2'
Usage: tests/target-variant.sh <target>

  target  Build target, e.g. nginx-debian-writable-latest or apache-debian-latest.
EOF2
}

if [ "${#}" -ne 1 ]; then
  usage >&2
  exit 2
fi
target="${1}"

case "${target}" in
*nginx*apache* | *apache*nginx*)
  printf 'Target %s names both nginx and apache\n' "${target}" >&2
  exit 2
  ;;
*nginx*) echo "nginx" ;;
*apache*) echo "apache" ;;
*)
  printf 'Target %s is neither an nginx nor an apache target\n' "${target}" >&2
  exit 2
  ;;
esac
