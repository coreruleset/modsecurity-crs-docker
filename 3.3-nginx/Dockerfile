FROM owasp/modsecurity:3

LABEL maintainer="Chaim Sanders <chaim.sanders@gmail.com>"

ARG COMMIT=v3.3/dev
ARG BRANCH=v3.3/dev
ARG REPO=SpiderLabs/owasp-modsecurity-crs
ENV WEBSERVER=Nginx
ENV PARANOIA=1
ENV ANOMALY_INBOUND=5
ENV ANOMALY_OUTBOUND=4

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

COPY docker-entrypoint.sh /

EXPOSE 80

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
