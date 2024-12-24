#!/usr/bin/env bash

# The purpose of this script is to test that `configure-rules.sh` will run
# successfully for all variables that we configure.

set -e

conf_file="${1}"
env_file="${2}"

if [ -f "${env_file}" ]; then
  rm "${env_file}"
fi

while read -r line; do
  if [ -z "${line}" ] || echo "${line}" | grep -Eq "^#"; then
    continue
  fi

  var_name="$(cut -d'|' -f2 <<< "${line}")"
  test_value="$(cut -d'|' -f5 <<< "${line}")"
  echo "Setting ${var_name}=${test_value}"
  echo "${var_name}=${test_value}" >> "${env_file}"
done < "${conf_file}"
