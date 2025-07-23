#!/bin/sh
# vim:sw=2:ts=2:sts=2:et

set -e

LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Legacy variable fallback
RESOLVERS=${RESOLVERS:-$DNS_SERVER}

# DNS_SERVER is unbound if not set. From now on, error on unbound variables
set -u

if [ -z "${RESOLVERS}" ]; then
  # If unset, use all nameserver entries from /etc/resolv.conf as default.
  # Note that /etc/resolv.conf supports both IPv4 and IPv6 but no port suffix.
  # IPv6 notation does not use brackets.
  RESOLVERS="$(grep -i '^nameserver' /etc/resolv.conf | cut -d ' ' -f2)"
  # IPv6 addresses must be enclosed in brackets. Convert lines to space separated string.
  RESOLVERS="$(echo "${RESOLVERS}" | sed 's/\(.*:.*\)/[\1]/' | xargs)"
fi

sed -i.bak -r "s/RESOLVERS/${RESOLVERS}/" /etc/nginx/nginx.conf
sed -i.bak -r "s/RESOLVER_CONFIG/${RESOLVER_CONFIG}/" /etc/nginx/nginx.conf
