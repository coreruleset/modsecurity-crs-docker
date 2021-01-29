FROM owasp/modsecurity:3

LABEL maintainer="Chaim Sanders <chaim.sanders@gmail.com>"

ARG COMMIT=v3.3/dev
ARG BRANCH=v3.3/dev
ARG REPO=coreruleset/coreruleset

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

COPY 3.3-nginx/docker-entrypoint.sh /
COPY 3.3-nginx/nginx.conf /etc/nginx/nginx.conf
COPY src/opt/modsecurity/activate-rules.sh /opt/modsecurity/
COPY src/etc/modsecurity.d/*.conf /etc/modsecurity.d/

RUN apt-get update \
 && apt-get -y install \
      ca-certificates \
      git \
      iproute2 \
      moreutils \
 && mkdir /opt/owasp-crs \
 && cd /opt/owasp-crs \
 && git init \
 && git remote add origin https://github.com/${REPO} \
 && git fetch --depth 1 origin ${BRANCH} \
 && git checkout ${COMMIT} \
 && mv -v crs-setup.conf.example crs-setup.conf \
 && ln -sv /opt/owasp-crs /etc/modsecurity.d/

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
