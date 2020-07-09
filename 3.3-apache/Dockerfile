FROM owasp/modsecurity:2

LABEL maintainer="Chaim Sanders <chaim.sanders@gmail.com>"

ARG COMMIT=v3.3/master
ARG BRANCH=v3.3/master
ARG REPO=coreruleset/coreruleset

ENV PARANOIA=1 \
    ANOMALY_INBOUND=5 \
    ANOMALY_OUTBOUND=4 \
    APACHE_TIMEOUT=60 \
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
    MODSEC_RESP_BODY_LIMIT=1048576 \
    MODSEC_PCRE_MATCH_LIMIT=100000 \
    MODSEC_PCRE_MATCH_LIMIT_RECURSION=100000

COPY src/etc/modsecurity.d/*.conf /etc/modsecurity.d/
COPY src/opt/modsecurity/activate-rules.sh /opt/modsecurity/
COPY 3.3-apache/conf/extra/*.conf /usr/local/apache2/conf/extra/
COPY 3.3-apache/docker-entrypoint.sh /

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
 && sed -i -E 's/(Listen) [0-9]+/\1 ${PORT}/g' /usr/local/apache2/conf/httpd.conf

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["apachectl", "-D", "FOREGROUND"]
