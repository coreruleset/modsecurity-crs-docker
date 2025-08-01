FROM image AS build

ARG NGINX_VERSION="n/a"
ARG MODSEC3_VERSION="n/a"
ARG MODSEC3_FLAGS="n/a"
ARG LMDB_VERSION="n/a"
ARG LUA_VERSION="n/a"
ARG NGINX_DYNAMIC_MODULES="n/a"
ARG NGINX_HOME="n/a"
ARG READ_ONLY_FS="false"

USER root

RUN set -eux; \
    echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections; \
    apt-get update -qq; \
    LD_LIBRARY_PATH="" apt-get install -y -qq --no-install-recommends --no-install-suggests \
        automake \
        cmake \
        doxygen \
        g++ \
        git \
        libcurl4-gnutls-dev \
        libfuzzy-dev \
        liblua${LUA_VERSION}-dev \
        libpcre2-dev \
        libtool \
        libxml2-dev \
        libmaxminddb-dev \
        libyajl-dev \
        make \
        patch \
        pkg-config \
        ruby \
        zlib1g-dev; \
     apt-get clean; \
     rm -rf /var/lib/apt/lists/*

WORKDIR /sources

RUN set -eux; \
    git clone https://github.com/LMDB/lmdb --branch LMDB_${LMDB_VERSION} --depth 1; \
    make -C lmdb/libraries/liblmdb install; \
    strip /usr/local/lib/liblmdb*.so*


RUN set -eux; \
    git clone https://github.com/owasp-modsecurity/ModSecurity --branch "v${MODSEC3_VERSION}" --depth 1 --recursive; \
    cd ModSecurity; \
    ARCH=$(gcc -print-multiarch); \
    sed -ie "s/i386-linux-gnu/${ARCH}/g" build/ssdeep.m4; \
    sed -ie "s/i386-linux-gnu/${ARCH}/g" build/pcre2.m4; \
    ./build.sh; \
    ./configure ${MODSEC3_FLAGS}; \
    make -j$(nproc) install; \
    strip /usr/local/modsecurity/lib/lib*.so*

# Build modules
RUN set -eux; \
    modules=""; \
    set -- ${NGINX_DYNAMIC_MODULES}; \
    while [ ${#} -gt 0 ]; \
    do \
        owner="${1}"; \
        name="${2}"; \
        version="${3}"; \
        shift 3; \
        git clone -b "${version}" --depth 1 "https://github.com/${owner}/${name}.git"; \
        modules="${modules} --add-dynamic-module=../${name}"; \
    done; \
    curl -sSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -o nginx-${NGINX_VERSION}.tar.gz; \
    tar -xzf nginx-${NGINX_VERSION}.tar.gz; \
    cd ./nginx-${NGINX_VERSION}; \
    ./configure --with-compat ${modules}; \
    make -j$(nproc) modules; \
    strip objs/*.so; \
    cp objs/*.so /etc/nginx/modules/; \
    mkdir /etc/modsecurity.d; \
    curl -sSL https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/unicode.mapping \
         -o /etc/modsecurity.d/unicode.mapping

# Generate/Download Diffie-Hellman parameter files
RUN set -eux; \
    mkdir -p /usr/share/TLS; \
    curl -sSL https://ssl-config.mozilla.org/ffdhe2048.txt -o /usr/share/TLS/dhparam-2048.pem; \
    curl -sSL https://ssl-config.mozilla.org/ffdhe4096.txt -o /usr/share/TLS/dhparam-4096.pem

FROM image AS crs_release

ARG CRS_RELEASE

USER root

# hadolint ignore=DL3008,SC2016
RUN set -eux; \
    apt-get update; \
    apt-get -y install --no-install-recommends \
      ca-certificates \
      curl \
      gnupg; \
    mkdir /opt/owasp-crs; \
    chown nginx:nginx /opt/owasp-crs

USER nginx

WORKDIR /sources

RUN curl -sSL https://github.com/coreruleset/coreruleset/releases/download/v${CRS_RELEASE}/coreruleset-${CRS_RELEASE}-minimal.tar.gz -o v${CRS_RELEASE}-minimal.tar.gz; \
    curl -sSL https://github.com/coreruleset/coreruleset/releases/download/v${CRS_RELEASE}/coreruleset-${CRS_RELEASE}-minimal.tar.gz.asc -o coreruleset-${CRS_RELEASE}-minimal.tar.gz.asc; \
    gpg --fetch-key https://coreruleset.org/security.asc; \
    gpg --verify coreruleset-${CRS_RELEASE}-minimal.tar.gz.asc v${CRS_RELEASE}-minimal.tar.gz; \
    tar -zxf v${CRS_RELEASE}-minimal.tar.gz --strip-components=1 -C /opt/owasp-crs; \
    rm -f v${CRS_RELEASE}-minimal.tar.gz coreruleset-${CRS_RELEASE}-minimal.tar.gz.asc; \
    mv -v /opt/owasp-crs/crs-setup.conf.example /opt/owasp-crs/crs-setup.conf

FROM image

ARG MODSEC3_VERSION
ARG LMDB_VERSION
ARG LUA_VERSION
ARG LUA_MODULES
ARG NGINX_HOME
ARG READ_ONLY_FS

LABEL maintainer="Felipe Zipitria <felipe.zipitria@owasp.org>"

ENV NGINX_HOME="${NGINX_HOME}"

ENV \
    ACCESSLOG=/var/log/nginx/access.log \
    BACKEND=http://localhost:80 \
    CORS_HEADER_403_ALLOW_ORIGIN="*" \
    CORS_HEADER_403_ALLOW_METHODS="GET, POST, PUT, DELETE, OPTIONS" \
    CORS_HEADER_403_CONTENT_TYPE="text/plain" \
    CORS_HEADER_403_MAX_AGE=3600 \
    CORS_HEADER_ACCESS_CONTROL_ALLOW_HEADERS="*" \
    ERRORLOG=/var/log/nginx/error.log \
    KEEPALIVE_TIMEOUT=60s \
    LD_LIBRARY_PATH=/lib:/usr/lib:/usr/local/lib \
    LOGLEVEL=warn \
    METRICS_ALLOW_FROM='127.0.0.0/24' \
    METRICS_DENY_FROM='all' \
    METRICSLOG=/dev/null \
    MODSEC_ARGUMENT_SEPARATOR="&" \
    MODSEC_ARGUMENTS_LIMIT=1000 \
    MODSEC_AUDIT_ENGINE="RelevantOnly" \
    MODSEC_AUDIT_LOG=/dev/stdout \
    MODSEC_AUDIT_LOG_FORMAT=JSON \
    MODSEC_AUDIT_LOG_PARTS='ABIJDEFHZ' \
    MODSEC_AUDIT_LOG_RELEVANT_STATUS="^(?:5|4(?!04))" \
    MODSEC_AUDIT_LOG_TYPE=Serial \
    MODSEC_COOKIE_FORMAT=0 \
    MODSEC_AUDIT_STORAGE_DIR=/var/log/modsecurity/audit/ \
    MODSEC_DATA_DIR=/tmp/modsecurity/data \
    MODSEC_DEBUG_LOG=/dev/null \
    MODSEC_DEBUG_LOGLEVEL=0 \
    MODSEC_DEFAULT_PHASE1_ACTION="phase:1,pass,log,tag:'\${MODSEC_TAG}'" \
    MODSEC_DEFAULT_PHASE2_ACTION="phase:2,pass,log,tag:'\${MODSEC_TAG}'" \
    MODSEC_DISABLE_BACKEND_COMPRESSION="Off" \
    MODSEC_PCRE_MATCH_LIMIT=100000 \
    MODSEC_PCRE_MATCH_LIMIT_RECURSION=100000 \
    MODSEC_REQ_BODY_ACCESS=on \
    MODSEC_REQ_BODY_JSON_DEPTH_LIMIT=512 \
    MODSEC_REQ_BODY_LIMIT=13107200 \
    MODSEC_REQ_BODY_LIMIT_ACTION="Reject" \
    MODSEC_REQ_BODY_NOFILES_LIMIT=131072 \
    MODSEC_RESP_BODY_ACCESS=on \
    MODSEC_RESP_BODY_LIMIT=1048576 \
    MODSEC_RESP_BODY_LIMIT_ACTION="ProcessPartial" \
    MODSEC_RESP_BODY_MIMETYPE="text/plain text/html text/xml" \
    MODSEC_RULE_ENGINE=on \
    MODSEC_STATUS_ENGINE="Off" \
    MODSEC_TAG=modsecurity \
    MODSEC_TMP_DIR=/tmp/modsecurity/tmp \
    MODSEC_TMP_SAVE_UPLOADED_FILES="on" \
    MODSEC_UNICODE_MAPPING=20127 \
    MODSEC_UPLOAD_DIR=/tmp/modsecurity/upload \
    MODSEC_UPLOAD_FILE_MODE=0600 \
    MODSEC_UPLOAD_KEEP_FILES=Off \
    NGINX_ALWAYS_TLS_REDIRECT=off \
    NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx \
    PORT=8080 \
    PROXY_SSL_CERT=/etc/nginx/conf/proxy.crt \
    PROXY_SSL_CERT_KEY=/etc/nginx/conf/proxy.key \
    PROXY_SSL_CIPHERS="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384" \
    PROXY_SSL=off \
    PROXY_SSL_PROTOCOLS="TLSv1.2 TLSv1.3" \
    PROXY_SSL_VERIFY_DEPTH=1 \
    PROXY_SSL_VERIFY=off \
    PROXY_TIMEOUT=60s \
    REAL_IP_HEADER="X-REAL-IP" \
    REAL_IP_PROXY_HEADER="X-REAL-IP" \
    REAL_IP_RECURSIVE="on" \
    RESOLVERS= \
    RESOLVER_CONFIG="valid=5s"\
    SERVER_NAME=localhost \
    SERVER_TOKENS=off \
    SET_REAL_IP_FROM="127.0.0.1" \
    SSL_CERT=/etc/nginx/conf/server.crt \
    SSL_CERT_KEY=/etc/nginx/conf/server.key \
    SSL_CIPHERS="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384" \
    SSL_DH_BITS=2048 \
    SSL_OCSP_STAPLING=on \
    SSL_PORT=8443 \
    SSL_PREFER_CIPHERS=off \
    SSL_PROTOCOLS="TLSv1.2 TLSv1.3" \
    SSL_VERIFY_DEPTH=1 \
    SSL_VERIFY=off \
    WORKER_CONNECTIONS=1024 \
    # CRS specific variables
    ANOMALY_INBOUND=5 \
    ANOMALY_OUTBOUND=4 \
    BLOCKING_PARANOIA=1

COPY --from=build /usr/local/modsecurity/lib/libmodsecurity.so.${MODSEC3_VERSION} /usr/local/modsecurity/lib/
COPY --from=build /etc/nginx/modules/*.so /etc/nginx/modules/
COPY --from=build /usr/local/lib/liblmdb.so /usr/local/lib/
COPY --from=build /usr/share/TLS/dhparam-* /etc/ssl/certs/
COPY --from=build /etc/modsecurity.d/unicode.mapping /etc/modsecurity.d/unicode.mapping
COPY --from=crs_release /opt/owasp-crs /opt/owasp-crs
COPY src/etc/modsecurity.d/modsecurity.conf /etc/nginx/templates/modsecurity.d/modsecurity.conf.template
COPY src/etc/modsecurity.d/modsecurity-override.conf /etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template
COPY src/etc/modsecurity.d/setup.conf /etc/nginx/templates/modsecurity.d/setup.conf.template
COPY nginx/docker-entrypoint.d/*.sh /docker-entrypoint.d/
COPY src/opt/modsecurity/activate-plugins.sh /docker-entrypoint.d/94-activate-plugins.sh
COPY src/opt/modsecurity/configure-rules.sh /docker-entrypoint.d/95-configure-rules.sh
COPY src/opt/modsecurity/configure-rules.conf /docker-entrypoint.d/
# We use the templating mechanism from the nginx image here.
COPY nginx/templates /etc/nginx/templates/
COPY src/bin/* /usr/local/bin/

USER root

RUN set -eux; \
    echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections; \
    apt-get update -qq; \
    LD_LIBRARY_PATH="" apt-get install -y -qq --no-install-recommends --no-install-suggests \
        ca-certificates \
        curl \
        ed \
        libcurl4-gnutls-dev \
        libfuzzy2 \
        liblua${LUA_VERSION} \
        ${LUA_MODULES} \
        libpcre2-8-0 \
        libxml2 \
        libyajl2 \
        libmaxminddb-dev \
        moreutils; \
    rm -rf /var/lib/apt/lists/*; \
    apt-get clean; \
    mkdir /etc/nginx/ssl; \
    # Comment out the SecDisableBackendCompression option since it is not supported in V3
    sed -i 's/^\(SecDisableBackendCompression .*\)/# \1/' /etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template; \
    ln -s /usr/local/modsecurity/lib/libmodsecurity.so.${MODSEC3_VERSION} /usr/local/modsecurity/lib/libmodsecurity.so.3.0; \
    ln -s /usr/local/modsecurity/lib/libmodsecurity.so.${MODSEC3_VERSION} /usr/local/modsecurity/lib/libmodsecurity.so.3; \
    ln -s /usr/local/modsecurity/lib/libmodsecurity.so.${MODSEC3_VERSION} /usr/local/modsecurity/lib/libmodsecurity.so; \
    ln -sv /opt/owasp-crs /etc/modsecurity.d/

RUN set -eux; \
    if [ "${READ_ONLY_FS}" = "true" ]; then \
        # move files that need to be writable so we can use tmpfs for them later
        mkdir -p /usr/local/bootstrap/nginx /usr/local/bootstrap/modsecurity.d /usr/local/bootstrap/owasp-crs; \
        mv "${NGINX_HOME}/"* /usr/local/bootstrap/nginx/; \
        mv /etc/modsecurity.d/* /usr/local/bootstrap/modsecurity.d/; \
        mv /opt/owasp-crs/* /usr/local/bootstrap/owasp-crs/; \
        chown nginx:nginx \
            "${NGINX_HOME}" \
            /usr/local/bootstrap/*; \
    else \
        # only run this script in read-only configuration
        rm /docker-entrypoint.d/0-move-writables.sh; \
    fi; \
    chown nginx:nginx \
        /opt/owasp-crs \
        /etc/modsecurity.d

USER nginx

RUN mkdir -p /tmp/modsecurity/data; \
    mkdir -p /tmp/modsecurity/upload; \
    mkdir -p /tmp/modsecurity/tmp

HEALTHCHECK CMD /usr/local/bin/healthcheck
