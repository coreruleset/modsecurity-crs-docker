#!/bin/sh -e

/usr/local/bin/generate-certicate /usr/local/apache2

. /opt/modsecurity/activate-plugins.sh
. /opt/modsecurity/activate-rules.sh

exec "$@"
