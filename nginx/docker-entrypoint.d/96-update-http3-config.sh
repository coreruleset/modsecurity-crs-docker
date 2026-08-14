#!/bin/sh
# vim:sw=2:ts=2:sts=2:et

set -eu

LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

HTTP3_CONFIG=""
if [ "${HTTP3}" = "on" ]; then
    HTTP3_ALT_SVC_PORT="${HTTP3_ALT_SVC_PORT:-${SSL_PORT}}"
    HTTP3_CONFIG="listen ${SSL_PORT} quic reuseport; http3 on; quic_retry on; add_header Alt-Svc 'h3=\":${HTTP3_ALT_SVC_PORT}\"; ma=86400' always;"
fi

sed -ir 's#HTTP3_CONFIG#'"${HTTP3_CONFIG}"'#' /etc/nginx/conf.d/default.conf
