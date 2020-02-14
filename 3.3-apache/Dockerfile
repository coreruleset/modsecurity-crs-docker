FROM owasp/modsecurity:2

LABEL maintainer="Chaim Sanders <chaim.sanders@gmail.com>"

ARG COMMIT=v3.3/dev
ARG BRANCH=v3.3/dev
ARG REPO=SpiderLabs/owasp-modsecurity-crs

ENV WEBSERVER=Apache \
    PARANOIA=1 \
    ANOMALY_INBOUND=5 \
    ANOMALY_OUTBOUND=4 \
    TIMEOUT=60 \
    LOGLEVEL=warn \
    ERRORLOG='/proc/self/fd/2' \
    USER=daemon \
    GROUP=daemon \
    SERVERADMIN=root@localhost \
    SERVERNAME=localhost \
    PORT=80 \
    MODSEC_RULE_ENGINE=on \
    MODSEC_REQ_BODY_ACCESS=on \
    MODSEC_REQ_BODY_LIMIT=13107200 \
    MODSEC_REQ_BODY_NOFILES_LIMIT=131072 \
    MODSEC_RESP_BODY_ACCESS=on \
    MODSEC_RESP_BODY_LIMIT=524288 \
    MODSEC_PCRE_MATCH_LIMIT=1000 \
    MODSEC_PCRE_MATCH_LIMIT_RECURSION=1000

RUN apt-get update \
 && apt-get -y install \
      ca-certificates \
      git \
      iproute2 \
 && mkdir /opt/owasp-crs \
 && cd /opt/owasp-crs \
 && git init \
 && git remote add origin https://github.com/${REPO} \
 && git fetch --depth 1 origin ${BRANCH} \
 && git checkout ${COMMIT} \
 && mv -v crs-setup.conf.example crs-setup.conf \
 && ln -sv /opt/owasp-crs /etc/modsecurity.d/ \
 && echo 'Include /etc/modsecurity.d/owasp-crs/crs-setup.conf' > /etc/modsecurity.d/include.conf \
 && echo 'Include /etc/modsecurity.d/owasp-crs/rules/*.conf'  >> /etc/modsecurity.d/include.conf \
 && sed -i /etc/modsecurity.d/modsecurity.conf \
      -e 's/SecRuleEngine DetectionOnly/SecRuleEngine On/g'

COPY httpd-*.conf /usr/local/apache2/conf/extra/
COPY modsecurity.conf /etc/modsecurity.d/
COPY docker-entrypoint.sh /

EXPOSE ${PORT}
EXPOSE 443

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["apachectl", "-D", "FOREGROUND"]
