#!/bin/sh -e

/usr/local/bin/generate-certificate /usr/local/apache2
/usr/local/bin/check-low-port

/opt/modsecurity/activate-plugins.sh
/opt/modsecurity/configure-rules.sh

if [ "$USE_FOLINIS_MODSEC_LOGFORMAT" = "true" ]; then
    # The rule feeding the format its ModSecurity values ships commented out.
    sed -i 's/^#LOGFORMAT#//' /etc/modsecurity.d/modsecurity-logformat.conf
    export APACHE_LOGFORMAT='"%h %{GEOIP_COUNTRY_CODE}e %u [%{%Y-%m-%d %H:%M:%S}t.%{usec_frac}t] \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{Content-Type}i\" %{remote}p %v %A %p %R %{BALANCER_WORKER_ROUTE}e %X \"%{cookie}n\" %{UNIQUE_ID}e %{SSL_PROTOCOL}x %{SSL_CIPHER}x %I %O %{ratio}n%% %D %{ModSecTimeIn}e %{ApplicationTime}e %{ModSecTimeOut}e %{ModSecAnomalyScoreInPLs}e %{ModSecAnomalyScoreOutPLs}e %{ModSecAnomalyScoreIn}e %{ModSecAnomalyScoreOut}e"'
fi

exec "$@"
