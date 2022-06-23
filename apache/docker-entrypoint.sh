#!/bin/sh -e

. /opt/modsecurity/activate-rules.sh

exec "$@"
