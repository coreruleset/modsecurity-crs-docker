FROM owasp/modsecurity:2

LABEL maintainer="Chaim Sanders <chaim.sanders@gmail.com>"

ARG COMMIT=v3.3/dev
ARG BRANCH=v3.3/dev
ARG REPO=SpiderLabs/owasp-modsecurity-crs
ENV WEBSERVER=Apache
ENV PARANOIA=1
ENV ANOMALYIN=5
ENV ANOMALYOUT=4

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

COPY httpd-logging-before-modsec.conf /usr/local/apache2/conf/extra/
COPY httpd-logging-after-modsec.conf  /usr/local/apache2/conf/extra/
COPY docker-entrypoint.sh /

EXPOSE 80
EXPOSE 443

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["apachectl", "-D", "FOREGROUND"]
