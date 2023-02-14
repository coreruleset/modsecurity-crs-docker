#!/bin/sh
# vim:sw=2:ts=2:sts=2:et

set -eu

LC_ALL=C
ME=$( basename "$0" )
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

touch /etc/modsecurity.d/modsecurity-override.conf 2>/dev/null || { echo >&2 "$ME: error: can not modify /etc/modsecurity.d/modsecurity-override.conf (read-only file system?)"; exit 1; }

cp /etc/nginx/modsecurity.d/*.conf /etc/modsecurity.d 2>/dev/null || { echo >&2 "$ME: error: cannot copy config files to /etc/modsecurity.d"; exit 2; }

exit 0
