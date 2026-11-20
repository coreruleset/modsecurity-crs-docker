#!/usr/bin/env bash
# Writes the environment file for a target: every configurable CRS variable set
# to its test value (see .github/workflows/configure-rules-for-test.sh), for
# `docker run --env-file`.
#
# The file goes wherever it is asked to; callers use a temporary location and
# remove it, so that running the tests leaves nothing behind in the repository.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tests/write-target-env.sh <target> <env-file>

  target    Build target, e.g. nginx-debian-writable-latest.
  env-file  File to write; an existing file is replaced.
EOF
}

if [ "${#}" -ne 2 ]; then
  usage >&2
  exit 2
fi
target="${1}"
env_file="${2}"

repo_root="$(cd "$(dirname "${0}")/.." && pwd)"

# Get the major CRS version from the target: targets ending with "previous" are
# v3; all others are v4.
crs_version="v4"
if [[ "${target}" == *-previous ]]; then
  crs_version="v3"
fi

"${repo_root}/.github/workflows/configure-rules-for-test.sh" \
  "${repo_root}/src/opt/modsecurity/configure-rules.${crs_version}.conf" \
  "${repo_root}/README.md" \
  "${env_file}"
