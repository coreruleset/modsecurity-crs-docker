#!/bin/sh
# vim:sw=2:ts=2:sts=2:et

set -eu

LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

PROXY_SSL_CONFIG=""
if [ "${PROXY_SSL}" = "on" ]; then
    PROXY_SSL_CONFIG="include includes/proxy_backend_ssl.conf;"
fi

sed -i.bak -r 's#PROXY_SSL_CONFIG#'"${PROXY_SSL_CONFIG}"'#' /etc/nginx/conf.d/default.conf
