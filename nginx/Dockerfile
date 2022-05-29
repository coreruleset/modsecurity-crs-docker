FROM owasp/modsecurity:nginx as release

ARG RELEASE

# hadolint ignore=DL3008,SC2016
RUN set -eux; \
    apt-get update; \
    apt-get -y install --no-install-recommends \
      ca-certificates \
      curl \
      gnupg; \
    mkdir /opt/owasp-crs; \
    curl -SL https://github.com/coreruleset/coreruleset/archive/v${RELEASE}.tar.gz -o v${RELEASE}.tar.gz; \
    curl -SL https://github.com/coreruleset/coreruleset/releases/download/v${RELEASE}/coreruleset-${RELEASE}.tar.gz.asc -o coreruleset-${RELEASE}.tar.gz.asc; \
    gpg --fetch-key https://coreruleset.org/security.asc; \
    gpg --verify coreruleset-${RELEASE}.tar.gz.asc v${RELEASE}.tar.gz; \
    tar -zxf v${RELEASE}.tar.gz --strip-components=1 -C /opt/owasp-crs; \
    rm -f v${RELEASE}.tar.gz coreruleset-${RELEASE}.tar.gz.asc; \
    mv -v /opt/owasp-crs/crs-setup.conf.example /opt/owasp-crs/crs-setup.conf

FROM owasp/modsecurity:nginx

LABEL maintainer="Felipe Zipitria <felipe.zipitria@owasp.org>"

# overridden variables
ENV USER=nginx \
    MODSEC_PCRE_MATCH_LIMIT=100000 \
    MODSEC_PCRE_MATCH_LIMIT_RECURSION=100000

# CRS specific variables
ENV USER=nginx \
    PARANOIA=1 \
    ANOMALY_INBOUND=5 \
    ANOMALY_OUTBOUND=4 \
    BLOCKING_PARANOIA=1

# We use the templating mechanism from the nginx image here,
# as set up by owasp/modsecurity-docker
COPY nginx/templates /etc/nginx/templates/
COPY src/etc/modsecurity.d/setup.conf /etc/nginx/templates/modsecurity.d/setup.conf.template
COPY nginx/docker-entrypoint.d/*.sh /docker-entrypoint.d/
COPY src/opt/modsecurity/activate-rules.sh /docker-entrypoint.d/95-activate-rules.sh
COPY --from=release /opt/owasp-crs /opt/owasp-crs

RUN  set -eux; ln -sv /opt/owasp-crs /etc/modsecurity.d/
