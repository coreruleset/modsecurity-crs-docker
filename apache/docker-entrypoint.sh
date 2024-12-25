#!/bin/sh -e

/usr/local/bin/generate-certificate /usr/local/apache2
/usr/local/bin/check-low-port

/opt/modsecurity/activate-plugins.sh
/opt/modsecurity/configure-rules.sh

exec "$@"
