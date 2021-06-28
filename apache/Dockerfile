FROM owasp/modsecurity:2

LABEL maintainer="Chaim Sanders <chaim.sanders@gmail.com>"

ARG RELEASE=%%RELEASE%%

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
    MODSEC_DEFAULT_PHASE1_ACTION="phase:1,pass,log,tag:'\${MODSEC_TAG}'" \
    MODSEC_DEFAULT_PHASE2_ACTION="phase:2,pass,log,tag:'\${MODSEC_TAG}'" \
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
COPY apache/conf/extra/*.conf /usr/local/apache2/conf/extra/
COPY apache/docker-entrypoint.sh /

# Change default shell to bash
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008,SC2016
RUN apt-get update \
 && apt-get -y install --no-install-recommends \
      ca-certificates \
      curl \
      iproute2 \
 && mkdir /opt/owasp-crs \
 && curl -SL https://github.com/coreruleset/coreruleset/archive/${RELEASE}.tar.gz \
 | tar -zxf - --strip-components=1 -C /opt/owasp-crs \
 && mv -v /opt/owasp-crs/crs-setup.conf.example /opt/owasp-crs/crs-setup.conf \
 && ln -sv /opt/owasp-crs /etc/modsecurity.d/ \
 && sed -i -E 's/(Listen) [0-9]+/\1 ${PORT}/g' /usr/local/apache2/conf/httpd.conf \
 && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["apachectl", "-D", "FOREGROUND"]
