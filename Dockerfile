FROM owasp/modsecurity:2

LABEL maintainer="Chaim Sanders <chaim.sanders@gmail.com>"

ARG COMMIT=v3.3/dev
ARG REPO=SpiderLabs/owasp-modsecurity-crs

ENV PARANOIA=1
ENV ANOMALYIN=5
ENV ANOMALYOUT=4

RUN apt-get update \
 && apt-get -y install \
      ca-certificates \
      git \
      iproute2 \
      python \
 && git clone -b ${COMMIT} --depth 1 https://github.com/${REPO}.git /opt/owasp-crs \
 && ln -sv /opt/owasp-crs /etc/modsecurity.d/owasp-crs \
 && cd /opt/owasp-crs \
 && mv -v crs-setup.conf.example crs-setup.conf \
 && cd /etc/modsecurity.d \
 && echo 'Include modsecurity.d/owasp-crs/crs-setup.conf' > include.conf \
 && echo 'Include modsecurity.d/owasp-crs/rules/*.conf'  >> include.conf \
 && sed -i /etc/modsecurity.d/modsecurity.conf \
      -e 's/SecRuleEngine DetectionOnly/SecRuleEngine On/g' \
 && a2enmod \
      proxy \
      proxy_http

COPY proxy.conf /etc/modsecurity.d/proxy.conf
COPY docker-entrypoint.sh /

EXPOSE 80

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["apachectl", "-D", "FOREGROUND"]
