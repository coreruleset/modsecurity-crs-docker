#!/bin/sh -e

export DNS_SERVER=${DNS_SERVER:-$(grep -i '^nameserver' /etc/resolv.conf|head -n1|cut -d ' ' -f2)}

ENV_VARIABLES=$(awk 'BEGIN{for(v in ENVIRON) print "$"v}')

FILES="/etc/nginx/nginx.conf /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/logging.conf /etc/nginx/includes/location_common.conf /etc/modsecurity.d/modsecurity-override.conf"

for FILE in $FILES; do
    if [ -f "$FILE" ]; then
        envsubst "$ENV_VARIABLES" <"$FILE" | sponge "$FILE"
    fi
done

. /opt/modsecurity/activate-rules.sh

# Work around ModSecurity not supporting optional includes on NGiNX
# Note: we are careful here to not assume the existance of the "plugins"
# directory. It is being introduced with version 4 of CRS.
for suffix in "config" "before" "after"; do
    if [ -n "$(find /opt/owasp-crs -path "*plugins/*-${suffix}.conf")" ]; then
        # enable if there are config files
        sed -i "s/#\s*\(.+-${suffix}.conf\)/\1/" /etc/modsecurity.d/setup.conf
    else
        # disable if there are no config files
        sed -i "s/\([^#]+-${suffix}.conf\)/# \1/" /etc/modsecurity.d/setup.conf
    fi
done
exec "$@"
