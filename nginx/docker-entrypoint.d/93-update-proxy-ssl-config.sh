#!/bin/sh
# vim:sw=2:ts=2:sts=2:et

set -eu

LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

PROXY_SSL_CONFIG=""
if [ "${PROXY_SSL}" = "on" ]; then
    PROXY_SSL_CONFIG="include includes/proxy_backend_ssl.conf;"
    # The client certificate is only configured when both files are present,
    # so the default configuration starts without it.
    if [ -f "${PROXY_SSL_CERT_FILE:-}" ] && [ -f "${PROXY_SSL_CERT_KEY_FILE:-}" ]; then
        PROXY_SSL_CONFIG="${PROXY_SSL_CONFIG} include includes/proxy_backend_ssl_client_cert.conf;"
        echo "${0}: using proxy client certificate ${PROXY_SSL_CERT_FILE} and key ${PROXY_SSL_CERT_KEY_FILE}"
    else
        echo "${0}: proxy client certificate or key not found, starting without client certificate"
    fi
fi

sed -i.bak -r 's#PROXY_SSL_CONFIG#'"${PROXY_SSL_CONFIG}"'#' /etc/nginx/conf.d/default.conf
