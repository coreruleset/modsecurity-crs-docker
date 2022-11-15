#!/bin/sh -e

# Check if crs-setup.conf is overriden
if [ -n "${MANUAL_MODE}" ]; then
  echo "Using manual config mode"
  return; # Don't use exit on a sourced script
fi

# Plugins can be disabled entirely by setting CRS_DISABLE_PLUGINS.
if [ -n "${CRS_DISABLE_PLUGINS}" ]; then
    echo "Plugins will be disabled"
    return; # Don't use exit on a sourced script
fi

# Handle plugins if we have the files.
# Note: we are careful here to not assume the existance of the "plugins"
# directory. It is being introduced with version 4 of CRS.
for suffix in "config" "before" "after"; do
    if [ -n "$(find /opt/owasp-crs -path "/opt/owasp-crs/plugins/*-${suffix}.conf")" ]; then
        # enable if there are config files
        sed -i -E "s/^#\s*(.+-${suffix}\.conf)/\1/" /etc/modsecurity.d/setup.conf
    else
        # disable if there are no config files
        sed -i -E "s/^([^#]+-${suffix}\.conf)/# \1/" /etc/modsecurity.d/setup.conf
    fi
done

