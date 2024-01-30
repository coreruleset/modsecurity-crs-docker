#!/bin/sh
# vim:sw=2:ts=2:sts=2:et

set -eu

LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# split comma separated IP addresses into multiple `set_real_ip xxx;` lines
SET_REAL_IP_FROM="$(echo "${SET_REAL_IP_FROM}" | awk -F, '{for(i=1; i<=NF; i++) printf "set_real_ip_from "$i";\\n"}')"

sed -i.bak -r 's#SET_REAL_IP_FROM#'"${SET_REAL_IP_FROM}"'#' /etc/nginx/includes/proxy_backend.conf
