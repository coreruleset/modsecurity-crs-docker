#!/bin/sh -e

/usr/local/bin/generate-certificate /usr/local/apache2

if [ "${PORT}" -lt 1024 ] || [ "${SSL_PORT}" -lt 1024 ]; then
  echo "ERROR: you are using PORT=${PORT} and SSL_PORT=${SSL_PORT}"
  echo "Both nginx and httpd containers now run with an unprivileged user. This means that we cannot bind to ports below 1024, so you might need to correct your PORT and SSL_PORT settings. Now the defaults for both nginx and httpd are 8080 and 8443."
  echo "FIX:"
  echo "if you have a port mapping like"
  echo "ports:"
  echo " - \"80:80\""
  echo "then update it to use a port higher than 1024. Example:"
  echo " - \"80:8080\""
  echo "The same should be done for the SSL ports."
    
  exit 1
fi

. /opt/modsecurity/activate-plugins.sh
. /opt/modsecurity/activate-rules.sh

exec "$@"
