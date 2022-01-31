# ModSecurity Core Rule Set Docker Image

[![dockeri.co](http://dockeri.co/image/owasp/modsecurity-crs)](https://hub.docker.com/r/owasp/modsecurity-crs/)

[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Fcoreruleset%2Fmodsecurity-crs-docker%2Fbadge%3Fref%3Dmaster&style=flat)](https://actions-badge.atrox.dev/coreruleset/modsecurity-crs-docker/goto?ref=master
) [![GitHub issues](https://img.shields.io/github/issues-raw/coreruleset/modsecurity-crs-docker.svg)](https://github.com/coreruleset/modsecurity-crs-docker/issues
) [![GitHub PRs](https://img.shields.io/github/issues-pr-raw/coreruleset/modsecurity-crs-docker.svg)](https://github.com/coreruleset/modsecurity-crs-docker/pulls
) [![License](https://img.shields.io/github/license/coreruleset/modsecurity-crs-docker.svg)](https://github.com/coreruleset/modsecurity-crs-docker/blob/master/LICENSE)

## What is the Core Rule Set

The Core Rule Set (CRS) is a set of generic attack detection rules for use with ModSecurity or compatible web application firewalls.
ModSecurity is an open source, cross platform web application firewall (WAF) engine for Apache, IIS and Nginx.

## Supported tags and respective `Dockerfile` links

* `3-nginx`, `3.3-nginx`, `3.3.2-nginx`, `nginx` ([master/nginx/Dockerfile](https://github.com/coreruleset/modsecurity-crs-docker/blob/master/nginx/Dockerfile)) – *last stable ModSecurity v3 on Nginx 1.20 official stable base image, and latest stable Core Rule Set 3.3.2 *
* `3-apache`, `3.3-apache`, `3.3.2-apache`, `apache` ([master/apache/Dockerfile](https://github.com/coreruleset/modsecurity-crs-docker/blob/master/apache/Dockerfile)) –*last stable ModSecurity v2 on Apache 2.4 official stable base image, and latest stable Core Rule Set 3.3.2 *

## Supported variants

We have support for [alpine linux](https://www.alpinelinux.org/) variants of the base images. Just add `-alpine` and you will get it. Examples:

* `3-nginx-alpine`, `3.3-nginx-alpine`, `3.3.2-nginx-alpine`, `nginx-alpine` ([master/nginx/Dockerfile-alpine](https://github.com/coreruleset/modsecurity-crs-docker/blob/master/nginx/Dockerfile-alpine) – *last stable ModSecurity v3 on Nginx 1.20 official alpine stable base image, and latest stable Core Rule Set 3.3.2 *
* `3-apache-alpine`, `3.3-apache-alpine`, `3.3.2-apache-alpine`, `apache-alpine` ([master/apache/Dockerfile-alpine](https://github.com/coreruleset/modsecurity-crs-docker/blob/master/apache/Dockerfile-alpine)) – *last stable ModSecurity v2 on Apache 2.4 official alpine stable base image, and latest stable Core Rule Set 3.3.2 *

## Supported architectures

We added the [docker buildx](https://github.com/docker/buildx) support to our docker builds so additional architectures are supported now. As we create our containers based on the official apache and nginx ones, we can only support the architectures they support.

There is a new file `docker-bake.hcl` used for this purpose. To build for new platforms, just use this example:

```bash
$ docker buildx use $(docker buildx create --platform linux/amd64,linux/arm64,linux/arm/v8)
$ docker buildx bake -f docker-bake.hcl
```

## CRS Versions

> Hey, I used some specific git version with the containers? What happened?

You can achieve the same results just by getting any version you want, and using docker volumes. See this example:

```bash
$ git clone https://github.com/coreruleset/coreruleset.git myrules
$ cd myrules
$ git checkout ac2a0d1
$ docker run -p 80:80 -ti -e PARANOIA=4 -v ./rules:/opt/owasp-crs/rules:ro --rm owasp/modsecurity-crs
```

## Apache

The Apache webserver is configured via the `httpd-modsecurity.conf` file overriding directives from the base file.

## Environment Variables

The following environment variables are available to configure the CRS container:

| Name     | Description|
| -------- | ------------------------------------------------------------------- |
| PARANOIA | An integer indicating the paranoia level (Default: 1)               |
| BACKEND  | The backend address (and optional port) of the backend server. (Default: the container's default router, port 81) (Examples: 192.0.2.2, 192.0.2.2:80, http://172.17.0.1:8000) |
| EXECUTING_PARANOIA | An integer indicating the executing_paranoia_level (Default: paranoia level) |
| ENFORCE_BODYPROC_URLENCODED | A boolean indicating the enforce_bodyproc_urlencoded (Default: 0) |
| VALIDATE_UTF8_ENCODING | A boolean indicating the crs_validate_utf8_encoding (Default: 0) |
| ANOMALY_INBOUND | An integer indicating the inbound_anomaly_score_threshold (Default: 5) |
| ANOMALY_OUTBOUND | An integer indicating the outbound_anomaly_score_threshold (Default: 4) |
| ALLOWED_METHODS | A string indicating the allowed_methods (Default: GET HEAD POST OPTIONS) |
| ALLOWED_REQUEST_CONTENT_TYPE | A string indicating the allowed_request_content_type (Default: |application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/x-amf| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json| |application/octet-stream| |application/csp-report| |application/xss-auditor-report| |text/plain|) |
| ALLOWED_REQUEST_CONTENT_TYPE_CHARSET | A string indicating the allowed_request_content_type_charset (Default: utf-8\|iso-8859-1\|iso-8859-15\|windows-1252) |
| ALLOWED_HTTP_VERSIONS | A string indicating the allowed_http_versions (Default: HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0) |
| RESTRICTED_EXTENSIONS | A string indicating the restricted_extensions (Default: .asa/ .asax/ .ascx/ .axd/ .backup/ .bak/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .com/ .config/ .conf/ .cs/ .csproj/ .csr/ .dat/ .db/ .dbf/ .dll/ .dos/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .ini/ .key/ .licx/ .lnk/ .log/ .mdb/ .old/ .pass/ .pdb/ .pol/ .printer/ .pwd/ .resources/ .resx/ .sql/ .sys/ .vb/ .vbs/ .vbproj/ .vsdisco/ .webinfo/ .xsd/ .xsx/) |
| RESTRICTED_HEADERS | A string indicating the restricted_headers (Default: /proxy/ /lock-token/ /content-range/ /if/) |
| STATIC_EXTENSIONS | A string indicating the static_extensions (Default: /.jpg/ /.jpeg/ /.png/ /.gif/ /.js/ /.css/ /.ico/ /.svg/ /.webp/) |
| MAX_NUM_ARGS | An integer indicating the max_num_args (Default: unlimited) |
| ARG_NAME_LENGTH | An integer indicating the arg_name_length (Default: unlimited) |
| ARG_LENGTH | An integer indicating the arg_length (Default: unlimited) |
| TOTAL_ARG_LENGTH | An integer indicating the total_arg_length (Default: unlimited) |
| MAX_FILE_SIZE | An integer indicating the max_file_size (Default: unlimited) |
| COMBINED_FILE_SIZES | An integer indicating the combined_file_sizes (Default: unlimited) |
| APACHE_TIMEOUT | Apache integer value indicating the number of seconds before receiving and sending time out (Default: 60) |
| NGINX_KEEPALIVE_TIMEOUT | Nginx integer value indicating the number of seconds a keep-alive client connection will stay open on the server side (Default: 60) |
| LOGLEVEL | A string value controlling the number of messages logged to the error_log (Default: warn) |
| ERRORLOG | A string value indicating the location of the error log file (Default: '/proc/self/fd/2') |
| PORT | An integer value indicating the port where the webserver is listening to (Default: 80) |
| USER | A string value indicating the name (or #number) of the user to run httpd as (Default: daemon) |
| GROUP | Apache string value indicating the name (or #number) of the group to run httpd as (Default: daemon) |
| SERVERADMIN | A string value indicating the address where problems with the server should be e-mailed (Default: root@localhost) |
| SERVERNAME | A string value indicating the server name (Default: localhost) |
| MODSEC_RULE_ENGINE | ModSecurity string value enabling ModSecurity itself (Default: on) |
| MODSEC_REQ_BODY_ACCESS | ModSecurity string value allowing ModSecurity to access request bodies (Default: on) |
| MODSEC_REQ_BODY_LIMIT | ModSecurity integer value indicating the maximum request body size  accepted for buffering (Default: 13107200) |
| MODSEC_RESP_BODY_ACCESS | ModSecurity string value allowing ModSecurity to access response bodies (Default: on) |
| MODSEC_RESP_BODY_LIMIT | ModSecurity integer value indicating the maximum response body size  accepted for buffering (Default: 524288) |
| MODSEC_PCRE_MATCH_LIMIT | ModSecurity integer value indicating the limit for the number of internal executions in the PCRE function (Default: 1000) |
| MODSEC_PCRE_MATCH_LIMIT_RECURSION | ModSecurity integer value indicating the limit for the depth of recursion when calling PCRE function (Default: 1000) |
| MODSEC_DEFAULT_PHASE1_ACTION | ModSecurity string with the contents for the default action in phase 1 (Default: `'phase:1,log,auditlog,pass,tag:\'\${MODSEC_TAG}\''`) |
| MODSEC_DEFAULT_PHASE2_ACTION | ModSecurity string with the contents for the default action in phase 2 (Default: `'phase:2,log,auditlog,pass,tag:\'\${MODSEC_TAG}\''`) |
| CRS_ENABLE_TEST_MARKER | A boolean indicating whether to write test markers to the log file (Used for running the CRS test suite. Default: 0) |

## Notes regarding reverse proxy

In order to more easily test drive the CRS ruleset, we include support for an technique called [Reverse Proxy](https://en.wikipedia.org/wiki/Reverse_proxy). Using this technique, you keep your pre-existing web server online at a non-standard host and port, and then configure the CRS container to accept public traffic. The CRS container then proxies the traffic to your pre-existing webserver. This way, you can test out CRS with any web server. Some notes:

* Proxy is not enabled by default. You'll need to pass the `-e PROXY=1` environment variable to enable it.
* You'll want to configure your typical webserver to listen on your docker interface only (i.e. 172.17.0.1:81) so that public traffic doesn't reach it.
* Do not use 127.0.0.1 as an UPSTREAM address. The loopback interface inside the docker container is not the same interface as the one on docker host.
* Note that traffic coming through this proxy will look like it's coming from the wrong address. You may want to configure your pre-existing webserver to use the `X-Forwarded-For` HTTP header to populate the remote address field for traffic from the proxy.

## ModSecurity CRS Tuning

There are two possible ways to pass ModSecurity CRS tuning rules to the container:

* To map the ModSecurity tuning file(s) via volumes into the container during the run command
* To copy the ModSecurity tuning file(s) into the created container and then start the container

### Map ModSecurity tuning file via volume

```
docker run -dti --rm \
   -p 80:80 \
   -v /path/to/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf:/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf \
   -v /path/to/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf:/etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf \
   owasp/modsecurity-crs:apache
```

### Copy ModSecurity tuning file into created container

This example can be helpful when no volume mounts are possible (some CI pipelines).

```
docker create -ti --name modseccrs \
   -p 80:80 \
   owasp/modsecurity-crs:apache

docker cp /path/to/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf \
   modseccrs:/etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf

docker start modseccrs
```

## Full docker run example with all possible environment variables

```
docker run -dti 80:80 --rm \
   -e PARANOIA=1 \
   -e EXECUTING_PARANOIA=2 \
   -e ENFORCE_BODYPROC_URLENCODED=1 \
   -e ANOMALY_INBOUND=10 \
   -e ANOMALY_OUTBOUND=5 \
   -e ALLOWED_METHODS="GET POST PUT" \
   -e ALLOWED_REQUEST_CONTENT_TYPE="text/xml|application/xml|text/plain" \
   -e ALLOWED_REQUEST_CONTENT_TYPE_CHARSET="utf-8|iso-8859-1" \
   -e ALLOWED_HTTP_VERSIONS="HTTP/1.1 HTTP/2 HTTP/2.0" \
   -e RESTRICTED_EXTENSIONS=".cmd/ .com/ .config/ .dll/" \
   -e RESTRICTED_HEADERS="/proxy/ /if/" \
   -e STATIC_EXTENSIONS="/.jpg/ /.jpeg/ /.png/ /.gif/" \
   -e MAX_NUM_ARGS=128 \
   -e ARG_NAME_LENGTH=50 \
   -e ARG_LENGTH=200 \
   -e TOTAL_ARG_LENGTH=6400 \
   -e MAX_FILE_SIZE=100000 \
   -e COMBINED_FILE_SIZES=1000000 \
   -e PROXY=1 \
   -e APACHE_TIMEOUT=60 \
   -e LOGLEVEL=warn \
   -e ERRORLOG='/proc/self/fd/2' \
   -e USER=daemon \
   -e GROUP=daemon \
   -e SERVERADMIN=root@localhost \
   -e SERVERNAME=localhost \
   -e PORT=80 \
   -e MODSEC_RULE_ENGINE=on \
   -e MODSEC_REQ_BODY_ACCESS=on \
   -e MODSEC_REQ_BODY_LIMIT=13107200 \
   -e MODSEC_REQ_BODY_NOFILES_LIMIT=131072 \
   -e MODSEC_RESP_BODY_ACCESS=on \
   -e MODSEC_RESP_BODY_LIMIT=524288 \
   -e MODSEC_PCRE_MATCH_LIMIT=1000 \
   -e MODSEC_PCRE_MATCH_LIMIT_RECURSION=1000 \
   -e VALIDATE_UTF8_ENCODING=1 \
   -e CRS_ENABLE_TEST_MARKER=1
   owasp/modsecurity-crs:apache
```
