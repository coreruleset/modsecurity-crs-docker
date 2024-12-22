#!/bin/sh

# This script is compatible with busybox. ShellCheck requires the shebang
# to be `/bin/busybox sh`, but non-busybox shells will obviously choke on
# that. So we use `/bin/sh` to launch the "default" shell.

set -e

printf "# # #\nRunning CRS rule configuration\n- - -\n"

DIRECTORY="$(cd "$(dirname "$0")" && pwd)"

# Check if crs-setup.conf is overriden
if [ -n "${MANUAL_MODE}" ]; then
  echo "Using manual config mode"
  # Don't use exit on a sourced script
  return
fi


setup_conf_path="/etc/modsecurity.d/owasp-crs/crs-setup.conf"

set_value() {
  local rule="${1}"
  local var_name="${2}"
  local tx_var_name="${3}"
  local var_value="${4}"
  echo "Configuring ${rule} for ${var_name} with ${tx_var_name}=${var_value}"

  # For each rule, we do one pass to uncomment the rule (up to first blank line after the rule),
  # then a second pass to set the variable. We do two separate passes since the rule might
  # already be uncommented (by default in the file or due to having been uncommented in a previous step).
  if grep -Eq "#.*id:${rule}" "${setup_conf_path}"; then
    # commented, uncomment now
    ed -s "${setup_conf_path}" <<EOF 2 > /dev/null
/id:${rule}/
-
.,/^$/ s/#//
wq
EOF
  fi

  # uncommented, set var
  ed -s "${setup_conf_path}" <<EOF 2 > /dev/null
/id:${rule}/
/setvar:'\?tx\.${tx_var_name}=/
s/=.*"/=${var_value}"/
wq
EOF
}

should_set() {
  test -n "${1}"
}

can_set() {
  local rule="${1}"
  local tx_var_name="${2}"

  if ! grep -q "id:${rule}" "${setup_conf_path}"; then
    return 1
  elif ! grep -Eq "setvar:'?tx\.${tx_var_name}" "${setup_conf_path}"; then
    return 1
  else
    return 0
  fi
}

get_legacy() {
  echo "${1}" | awk -F'\|' '{print $1}'
}

get_var_name() {
  echo "${1}" | awk -F'\|' '{print $2}'
}

get_var_value() {
  # Get the variable name, produce "${<var name>}" and use eval to expand
  eval "echo $(echo "${1}" | awk -F'\|' '{print "${"$2"}"}')"
}

get_rule() {
  echo "${1}" | awk -F'\|' '{print $3}'
}

get_tx_var_name() {
  echo "${1}" | awk -F'\|' '{print $4}'
}

while read -r line; do
  if [ -z "${line}" ] || echo "${line}" | grep -Eq "^#"; then
    continue
  fi

  legacy="$(get_legacy "${line}")"
  var_name="$(get_var_name "${line}")"
  var_value="$(get_var_value "${line}")"
  rule="$(get_rule "${line}")"
  tx_var_name="$(get_tx_var_name "${line}")"

  if should_set "${var_value}" "${tx_var_name}"; then
    if ! can_set "${rule}" "${tx_var_name}"; then
      if [ "${legacy}" = "true" ]; then
        echo "Legacy variable set but nothing found to substitute. Skipping"
        continue
      fi
      echo "Failed to find rule ${rule} to set ${tx_var_name}=${var_value} for ${var_name} in ${setup_conf_path}. Aborting"
      exit 1
    fi

    set_value "${rule}" "${var_name}" "${tx_var_name}" "${var_value}"
  fi
done < "${DIRECTORY}/configure-rules.conf"

# Add SecDefaultActions
var="${MODSEC_DEFAULT_PHASE1_ACTION}"
if should_set "${var}"; then
  if ! grep -Eq "^SecDefaultAction.*phase:1" "${setup_conf_path}"; then
    echo "Failed to find definition of SecDefaultAction for phase 1 in ${setup_conf_path}. Aborting"
    exit 1
  fi
  ed -s "${setup_conf_path}" <<EOF 2 > /dev/null
/^SecDefaultAction.*phase:1/
s/".*"/"${var}"/
wq
EOF
fi
var="${MODSEC_DEFAULT_PHASE2_ACTION}"
if should_set "${var}"; then
  if ! grep -Eq "^SecDefaultAction.*phase:2" "${setup_conf_path}"; then
    echo "Failed to find definition of SecDefaultAction for phase 2 in ${setup_conf_path}. Aborting"
    exit 1
  fi
  ed -s "${setup_conf_path}" <<EOF 2 > /dev/null
/^SecDefaultAction.*phase:2/
s/".*"/"${var}"/
wq
EOF
fi

# Substitute MODSEC_TAG (part of the default phase actions above)
var="${MODSEC_TAG}"
if should_set "${var}"; then
  if ! grep -q "MODSEC_TAG" "${setup_conf_path}"; then
    echo "Failed to find definition of MODSEC_TAG in ${setup_conf_path}. Skipping"

  else
    sed -z -E -i "s/\\$\{MODSEC_TAG\}/${var}/g" "${setup_conf_path}"
  fi
fi


# Add marker rule for CRS test setup
# Add it only once
if [ -n "${CRS_ENABLE_TEST_MARKER}" ] && [ "${CRS_ENABLE_TEST_MARKER}" -eq 1 ] && ! grep -q id:999999 "${setup_conf_path}"; then
  cat <<EOF >> "${setup_conf_path}"


# Write the value from the X-CRS-Test header as a marker to the log
SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \\
    "id:999999,\\
    phase:1,\\
    pass,\\
    t:none,\\
    log,\\
    msg:'%{MATCHED_VAR}',\
    ctl:ruleRemoveById=1-999999"
EOF
fi

printf -- "- - -\nFinished CRS rule configuration\n# # #\n\n"
