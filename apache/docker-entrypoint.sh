#!/bin/sh -e

. /opt/modsecurity/activate-plugins.sh
. /opt/modsecurity/activate-rules.sh

exec "$@"
