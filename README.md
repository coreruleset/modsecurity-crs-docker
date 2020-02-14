# ModSecurity Core Rule Set Docker Image

[![dockeri.co](http://dockeri.co/image/owasp/modsecurity-crs)](https://hub.docker.com/r/owasp/modsecurity-crs/)

[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2FCRS-support%2Fmodsecurity-crs-docker%2Fbadge%3Fref%3Dmaster&style=flat)](https://actions-badge.atrox.dev/CRS-support/modsecurity-crs-docker/goto?ref=master
) [![GitHub issues](https://img.shields.io/github/issues-raw/CRS-support/modsecurity-crs-docker.svg)](https://github.com/CRS-support/modsecurity-crs-docker/issues
) [![GitHub PRs](https://img.shields.io/github/issues-pr-raw/CRS-support/modsecurity-crs-docker.svg)](https://github.com/CRS-support/modsecurity-crs-docker/pulls
) [![License](https://img.shields.io/github/license/CRS-support/modsecurity-crs-docker.svg)](https://github.com/CRS-support/modsecurity-crs-docker/blob/master/LICENSE)

## What is the Core Rule Set

The Core Rule Set (CRS) is a set of generic attack detection rules for use with ModSecurity or compatible web application firewalls.
ModSecurity is an open source, cross platform web application firewall (WAF) engine for Apache, IIS and Nginx.

## Example

```
docker build -t owasp/modsecurity-crs .
docker run -p 80:80 -ti -e PARANOIA=4 --rm owasp/modsecurity-crs
```

or

```
docker build -t owasp/modsecurity-crs .
docker run -p 80:80 -ti -e PARANOIA=4 -e PROXY=1 --rm owasp/modsecurity-crs
```
## Environment Variables

The following environment variables are available to configure the CRS container:

| Name     | Description|
| -------- | ------------------------------------------------------------------- |
| PARANOIA | An integer indicating the paranoia level (Default: 1)               |
| PROXY    | An integer indicating if reverse proxy mode is enabled (Default: 0) |
| UPSTREAM | The IP Address (and optional port) of the upstream server when proxy mode is enabled. (Default: the container's default router, port 81) (Examples: 192.0.2.2 or 192.0.2.2:80) |
| EXECUTING_PARANOIA | An integer indicating the executing_paranoia_level (Default: paranoia level) |
| ENFORCE_BODYPROC_URLENCODED | A boolean indicating the enforce_bodyproc_urlencoded (Default: 0) |
| ANOMALY_INBOUND | An integer indicating the inbound_anomaly_score_threshold (Default: 5) |
| ANOMALY_OUTBOUND | An integer indicating the outbound_anomaly_score_threshold (Default: 4) |
| ALLOWED_METHODS | A string indicating the allowed_methods (Default: GET HEAD POST OPTIONS) |
| ALLOWED_REQUEST_CONTENT_TYPE | A string indicating the allowed_request_content_type (Default: application/x-www-form-urlencoded\|multipart/form-data\|text/xml\|application/xml\|application/soap+xml\|application/x-amf\|application/json\|application/octet-stream\|application/csp-report\|application/xss-auditor-report\|text/plain) |
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
| TIMEOUT | Apache integer value indicating the number of seconds before receiving and sending time out (Default: 60) |
| LOGLEVEL | Apache string value controlling the number of messages logged to the error_log, Apache (Default: warn) |
| ERRORLOG | Apache string value indicating the location of the error log file (Default: '/proc/self/fd/2') |
| PORT | Apache integer value indicating the port where Apache is listening to (Default: 80) |
| USER | Apache string value indicating the name (or #number) of the user to run httpd as (Default: daemon) |
| GROUP | Apache string value indicating the name (or #number) of the group to run httpd as (Default: daemon) |
| SERVERADMIN | Apache string value indicating the address where problems with the server should be e-mailed (Default: root@localhost) |
| SERVERNAME | Apache string value indicating the server name (Default: localhost) |
| MODSEC_RULE_ENGINE | ModSecurity string value enabling ModSecurity itself (Default: on) |
| MODSEC_REQ_BODY_ACCESS | ModSecurity string value allowing ModSecurity to access request bodies (Default: on) |
| MODSEC_REQ_BODY_LIMIT | ModSecurity integer value indicating the maximum request body size  accepted for buffering (Default: 13107200) |
| MODSEC_RESP_BODY_ACCESS | ModSecurity string value allowing ModSecurity to access response bodies (Default: on) |
| MODSEC_RESP_BODY_LIMIT | ModSecurity integer value indicating the maximum response body size  accepted for buffering (Default: 524288) |
| MODSEC_PCRE_MATCH_LIMIT | ModSecurity integer value indicating the limit for the number of internal executions in the PCRE function (Default: 1000) |
| MODSEC_PCRE_MATCH_LIMIT_RECURSION | ModSecurity integer value indicating the limit for the depth of recursion when calling PCRE function (Default: 1000) |

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
   owasp/modsecurity-crs
```

### Copy ModSecurity tuning file into created container

This example can be helpful when no volume mounts are possible (some CI pipelines).

```
docker create -ti --name modseccrs \
   -p 80:80 \
   owasp/modsecurity-crs

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
   -e TIMEOUT=60 \
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
   -e MODSEC_PCRE_MATCH_LIMIT_RECURSION=1000
   owasp/modsecurity-crs
```
