#!/bin/sh
# vim:sw=2:ts=2:sts=2:et

set -eu

LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

DNS_SERVER="${DNS_SERVER:-$(grep -i '^nameserver' /etc/resolv.conf | head -n1 | cut -d ' ' -f2)}"

sed -i.bak -r 's/DNS_SERVER/'"${DNS_SERVER}"'/' /etc/nginx/nginx.conf
