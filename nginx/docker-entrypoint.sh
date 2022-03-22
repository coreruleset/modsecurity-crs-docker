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

# work around ModSecurity not supporting optional includes on NGiNX
if [ -d /opt/owasp-crs/plugins ]; then
    if ! [ -z "$(find /opt/owasp-crs/plugins -name "*-config.conf")" ]; then
        sed -i 's/#\(.*-config.conf\)/\1/' /etc/modsecurity.d/setup.conf
    fi
    if ! [ -z "$(find /opt/owasp-crs/plugins -name "*-before.conf")" ]; then
        sed -i 's/#\(.*-before.conf\)/\1/' /etc/modsecurity.d/setup.conf
    fi
    if ! [ -z "$(find /opt/owasp-crs/plugins -name "*-after.conf")" ]; then
        sed -i 's/#(\.*-after.conf\)/\1/' /etc/modsecurity.d/setup.conf
    fi
fi

exec "$@"
