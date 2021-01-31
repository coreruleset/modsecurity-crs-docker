#!/bin/bash

# Release will use master branch as stable

set -e

target="$1"

if [ -z "$target" ]; then
  echo "usage: $0 vX.Y-(apache|nginx)" >&2
  exit 1
fi

# relases might be release candidates, which are named with '-rcX'
release="${target%-*}"
server="${target#*-}"
server_no_rc="${server#*-}"

cd "$(dirname "$0")/.."
mkdir -p "${target}"


sed -e "s,%%RELEASE%%,${release},g" \
  "${server_no_rc}/Dockerfile" > "${target}/Dockerfile"

