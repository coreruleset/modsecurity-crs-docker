#!/bin/sh
# vim:sw=2:ts=2:sts=2:et

set -eu

LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

cp -r /usr/local/bootstrap/nginx/* "${NGINX_HOME}/"
cp -r /usr/local/bootstrap/modsecurity.d/* /etc/modsecurity.d/
cp -r /usr/local/bootstrap/owasp-crs/* /opt/owasp-crs/

exit 0