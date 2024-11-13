#!/bin/sh
# vim:sw=2:ts=2:sts=2:et

set -eu

LC_ALL=C
ME=$( basename "$0" )
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

/usr/local/bin/generate-certificate /usr/local/openresty/nginx/conf

exit 0
