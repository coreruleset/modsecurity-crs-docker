#!/bin/sh -e

setup_conf_path="/etc/modsecurity.d/owasp-crs/crs-setup.conf"

# Check if crs-setup.conf is overriden
if [ -n "${MANUAL_MODE}" ]; then
  echo "Using manual config mode"
  return; # Don't use exit on a sourced script
fi

# Paranoia Level
sed -z -E -i 's/#SecAction[^"]+"id:900000.*tx\.paranoia_level=1\"/SecAction \\\n  \"id:900000, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:tx.paranoia_level='"${PARANOIA}"'\"/' "${setup_conf_path}"

# Blocking Paranoia Level
if [ -n "${BLOCKING_PARANOIA}" ]; then
  sed -z -E -i 's/#SecAction[^"]+"id:900000.*tx\.blocking_paranoia_level=1\"/SecAction \\\n  \"id:900000, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:tx.blocking_paranoia_level='"${BLOCKING_PARANOIA}"'\"/' "${setup_conf_path}"
fi

# Executing Paranoia Level
if [ -n "${EXECUTING_PARANOIA}" ]; then
  sed -z -E -i 's/#SecAction[^"]+"id:900001.*tx\.executing_paranoia_level=1\"/SecAction \\\n  \"id:900001, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:tx.executing_paranoia_level='"${EXECUTING_PARANOIA}"'\"/' "${setup_conf_path}"
fi

# Detection Paranoia Level
if [ -n "${DETECTION_PARANOIA}" ]; then
  sed -z -E -i 's/#SecAction[^"]+"id:900001.*tx\.detection_paranoia_level=1\"/SecAction \\\n  \"id:900001, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:tx.detection_paranoia_level='"${DETECTION_PARANOIA}"'\"/' "${setup_conf_path}"
fi

# Enforce Body Processor URLENCODED
if [ -n "${ENFORCE_BODYPROC_URLENCODED}" ]; then
  sed -z -E -i 's/#SecAction[^"]+"id:900010.*tx\.enforce_bodyproc_urlencoded=1\"/SecAction \\\n  \"id:900010, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:tx.enforce_bodyproc_urlencoded='"${ENFORCE_BODYPROC_URLENCODED}"'\"/' "${setup_conf_path}"
fi

# Inbound and Outbound Anomaly Score
sed -z -E -i 's/#SecAction[^"]+"id:900110.*tx\.outbound_anomaly_score_threshold=4\"/SecAction \\\n  \"id:900110, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:tx.inbound_anomaly_score_threshold='"${ANOMALY_INBOUND}"',  \\\n   setvar:tx.outbound_anomaly_score_threshold='"${ANOMALY_OUTBOUND}"'\"/' "${setup_conf_path}"

# HTTP methods that a client is allowed to use.
if [ -n "${ALLOWED_METHODS}" ]; then
  sed -z -E -i 's/#SecAction[^"]+"id:900200.*\x27tx\.allowed_methods=[[:upper:][:space:]]*\x27\"/SecAction \\\n  \"id:900200, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:\x27tx.allowed_methods='"${ALLOWED_METHODS}"'\x27\"/' "${setup_conf_path}"
fi

# Content-Types that a client is allowed to send in a request.
if [ -n "${ALLOWED_REQUEST_CONTENT_TYPE}" ]; then
  sed -z -E -i 's;#SecAction[^"]+"id:900220.*\x27tx\.allowed_request_content_type=[[:lower:][:space:]|+/-]*\x27\";SecAction \\\n  \"id:900220, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:\x27tx.allowed_request_content_type='"${ALLOWED_REQUEST_CONTENT_TYPE}"'\x27\";' "${setup_conf_path}"
fi

# Content-Types charsets that a client is allowed to send in a request.
if [ -n "${ALLOWED_REQUEST_CONTENT_TYPE_CHARSET}" ]; then
  sed -z -E -i 's/#SecAction[^"]+"id:900280.*\x27tx\.allowed_request_content_type_charset=[[:lower:][:digit:]|-]*\x27\"/SecAction \\\n  \"id:900280, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:\x27tx.allowed_request_content_type_charset='"${ALLOWED_REQUEST_CONTENT_TYPE_CHARSET}"'\x27\"/' "${setup_conf_path}"
fi

# Allowed HTTP versions.
if [ -n "${ALLOWED_HTTP_VERSIONS}" ]; then
  sed -z -E -i 's|#SecAction[^"]+"id:900230.*\x27tx\.allowed_http_versions=[HTP012[:space:]/.]*\x27\"|SecAction \\\n  \"id:900230, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:\x27tx.allowed_http_versions='"${ALLOWED_HTTP_VERSIONS}"'\x27\"|' "${setup_conf_path}"
fi

# Forbidden file extensions.
if [ -n "${RESTRICTED_EXTENSIONS}" ]; then
  sed -z -E -i 's|#SecAction[^"]+"id:900240.*\x27tx\.restricted_extensions=[[:lower:][:space:]./]*\/\x27\"|SecAction \\\n  \"id:900240, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:\x27tx.restricted_extensions='"${RESTRICTED_EXTENSIONS}"'\x27\"|' "${setup_conf_path}"
fi

# Forbidden request headers basic.
if [ -n "${RESTRICTED_HEADERS_BASIC}" ]; then
  sed -z -E -i 's|#SecAction[^"]+"id:900250.*\x27tx\.restricted_headers_basic=[[:lower:][:space:]/-]*\x27\"|SecAction \\\n  \"id:900250, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:\x27tx.restricted_headers_basic='"${RESTRICTED_HEADERS_BASIC}"'\x27\"|' "${setup_conf_path}"
fi

# Forbidden request headers extended.
if [ -n "${RESTRICTED_HEADERS_EXTENDED}" ]; then
  sed -z -E -i 's|#SecAction[^"]+"id:900255.*\x27tx\.restricted_headers_extended=[[:lower:][:space:]/-]*\x27\"|SecAction \\\n  \"id:900255, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:\x27tx.restricted_headers_extended='"${RESTRICTED_HEADERS_EXTENDED}"'\x27\"|' "${setup_conf_path}"
fi

# File extensions considered static files.
if [ -n "${STATIC_EXTENSIONS}" ]; then
  sed -z -E -i 's|#SecAction[^"]+"id:900260.*\x27tx\.static_extensions=/[[:lower:][:space:]/.]*\x27\"|SecAction \\\n  \"id:900260, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:\x27tx.static_extensions='"${STATIC_EXTENSIONS}"'\x27\"|' "${setup_conf_path}"
fi

# Block request if number of arguments is too high
if [ -n "${MAX_NUM_ARGS}" ]; then
  sed -z -E -i 's/#SecAction[^"]+"id:900300.*tx\.max_num_args=255\"/SecAction \\\n  \"id:900300, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:tx.max_num_args='"${MAX_NUM_ARGS}"'\"/' "${setup_conf_path}"
fi

# Block request if the length of any argument name is too high
if [ -n "${ARG_NAME_LENGTH}" ]; then
  sed -z -E -i 's/#SecAction[^"]+"id:900310.*tx\.arg_name_length=100\"/SecAction \\\n \"id:900310, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:tx.arg_name_length='"${ARG_NAME_LENGTH}"'\"/' "${setup_conf_path}"
fi

# Block request if the length of any argument value is too high
if [ -n "${ARG_LENGTH}" ]; then
  sed -z -E -i 's/#SecAction[^"]+"id:900320.*tx\.arg_length=400\"/SecAction \\\n  \"id:900320, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:tx.arg_length='"${ARG_LENGTH}"'\"/' "${setup_conf_path}"
fi

# Block request if the total length of all combined arguments is too high
if [ -n "${TOTAL_ARG_LENGTH}" ]; then
  sed -z -E -i 's/#SecAction[^"]+"id:900330.*tx\.total_arg_length=64000\"/SecAction \\\n  \"id:900330, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n  t:none, \\\n   setvar:tx.total_arg_length='"${TOTAL_ARG_LENGTH}"'\"/' "${setup_conf_path}"
fi

# Block request if the total length of all combined arguments is too high
if [ -n "${MAX_FILE_SIZE}" ]; then
  sed -z -E -i 's/#SecAction[^"]+"id:900340.*tx\.max_file_size=1048576\"/SecAction \\\n  \"id:900340, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:tx.max_file_size='"${MAX_FILE_SIZE}"'\"/' "${setup_conf_path}"
fi

# Block request if the total size of all combined uploaded files is too high
if [ -n "${COMBINED_FILE_SIZES}" ]; then
  sed -z -E -i 's/#SecAction[^"]+"id:900350.*tx\.combined_file_sizes=1048576\"/SecAction \\\n  \"id:900350, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:tx.combined_file_sizes='"${COMBINED_FILE_SIZES}"'\"/' "${setup_conf_path}"
fi

# Activate UTF8 validation
if [ -n "${VALIDATE_UTF8_ENCODING}" ]; then
  sed -z -E -i 's/#SecAction[^"]+"id:900950.*tx\.crs_validate_utf8_encoding=1\"/SecAction \\\n  \"id:900950, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:tx.crs_validate_utf8_encoding=1\"/' "${setup_conf_path}"
fi

# Add SecDefaultActions
if [ -n "${MODSEC_DEFAULT_PHASE1_ACTION}" ]; then
  sed -z -E -i "s/SecDefaultAction \"phase:1,log,auditlog,pass\"/SecDefaultAction \"${MODSEC_DEFAULT_PHASE1_ACTION}\"/" "${setup_conf_path}"
fi

if [ -n "${MODSEC_DEFAULT_PHASE2_ACTION}" ]; then
  sed -z -E -i "s/SecDefaultAction \"phase:2,log,auditlog,pass\"/SecDefaultAction \"${MODSEC_DEFAULT_PHASE2_ACTION}\"/" "${setup_conf_path}"
fi

# Substitute MODSEC_TAG
if [ -n "${MODSEC_TAG}" ]; then
  sed -z -E -i "s/\\$\{MODSEC_TAG\}/${MODSEC_TAG}/g" "${setup_conf_path}"
fi

# Reporting Level
if [ -n "${REPORTING_LEVEL}" ]; then
  sed -z -E -i 's/#SecAction[^"]+"id:900115.*tx\.reporting_level=2\"/SecAction \\\n  \"id:900115, \\\n   phase:1, \\\n   nolog, \\\n   pass, \\\n   t:none, \\\n   setvar:tx.reporting_level='"${REPORTING_LEVEL}"'\"/' "${setup_conf_path}"
fi


# Add marker rule for CRS test setup
# Add it only once
if [ -n "${CRS_ENABLE_TEST_MARKER}" ] && [ ${CRS_ENABLE_TEST_MARKER} -eq 1 ] && ! grep -q id:999999 "${setup_conf_path}"; then
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
