#!/bin/sh
# vim:sw=2:ts=2:sts=2:et

set -eu

LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Whether the client certificate is used at all is decided by
# check-proxy-client-cert, shared with the Apache images.
rc=0
decision="$(check-proxy-client-cert "${NGINX_HOME:-/etc/nginx}/conf/proxy.crt" "${NGINX_HOME:-/etc/nginx}/conf/proxy.key")" || rc=$?

PROXY_SSL_CONFIG=""
case "${decision:-}" in
    cert)
        PROXY_SSL_CONFIG="include includes/proxy_backend_ssl.conf; include includes/proxy_backend_ssl_client_cert.conf;"
        ;;
    no-cert)
        PROXY_SSL_CONFIG="include includes/proxy_backend_ssl.conf;"
        ;;
    off)
        ;;
    *)
        exit "${rc}"
        ;;
esac

sed -i.bak -r 's#PROXY_SSL_CONFIG#'"${PROXY_SSL_CONFIG}"'#' /etc/nginx/conf.d/default.conf
