#!/bin/bash -e

ENV_VARIABLES=$(awk 'BEGIN{for(v in ENVIRON) print "$"v}')

for FILE in etc/nginx/nginx.conf etc/nginx/conf.d/default.conf etc/modsecurity.d/modsecurity-override.conf
do
    envsubst "$ENV_VARIABLES" <$FILE | sponge $FILE
done

source /opt/modsecurity/activate-rules.sh

exec "$@"
