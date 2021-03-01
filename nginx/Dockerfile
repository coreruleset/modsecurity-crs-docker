FROM owasp/modsecurity:3

LABEL maintainer="Chaim Sanders <chaim.sanders@gmail.com>"

ARG RELEASE=%%RELEASE%%

ENV PARANOIA=1 \
    ANOMALY_INBOUND=5 \
    ANOMALY_OUTBOUND=4 \
    NGINX_KEEPALIVE_TIMEOUT=60s \
    ERRORLOG=/var/log/nginx/error.log \
    LOGLEVEL=warn \
    USER=nginx \
    PORT=80 \
    SERVERNAME=locahost \
    WORKER_CONNECTIONS=1024 \
    MODSEC_RULE_ENGINE=on \
    MODSEC_REQ_BODY_ACCESS=on \
    MODSEC_REQ_BODY_LIMIT=13107200 \
    MODSEC_REQ_BODY_NOFILES_LIMIT=131072 \
    MODSEC_RESP_BODY_ACCESS=on \
    MODSEC_RESP_BODY_LIMIT=1048576 \
    MODSEC_PCRE_MATCH_LIMIT=100000 \
    MODSEC_PCRE_MATCH_LIMIT_RECURSION=100000

COPY src/opt/modsecurity/activate-rules.sh /opt/modsecurity/
COPY src/etc/modsecurity.d/*.conf /etc/modsecurity.d/
COPY nginx/docker-entrypoint.sh /
COPY nginx/nginx.conf /etc/nginx/nginx.conf

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
 && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
