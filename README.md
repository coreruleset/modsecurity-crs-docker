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

* `3-nginx-YYYYMMDDHHMM`, `3.3-nginx-YYYYMMDDHHMM`, `3.3.5-nginx-YYYYMMDDHHMM`, `nginx` ([master/nginx/Dockerfile](https://github.com/coreruleset/modsecurity-crs-docker/blob/master/nginx/Dockerfile)) – *last stable ModSecurity v3 on Nginx 1.24 official stable base image, and latest stable Core Rule Set 3.3.5*
* `3-apache-YYYYMMDDHHMM`, `3.3-apache-YYYYMMDDHHMM`, `3.3.5-apache-YYYYMMDDHHMM`, `apache` ([master/apache/Dockerfile](https://github.com/coreruleset/modsecurity-crs-docker/blob/master/apache/Dockerfile)) –*last stable ModSecurity v2 on Apache 2.4.56 official stable base image, and latest stable Core Rule Set 3.3.5*

⚠️ We changed tags to [support production usage](https://github.com/coreruleset/modsecurity-crs-docker/issues/67). Now, if you want to use the "rolling version", use the tag `owasp/modsecurity-crs:nginx` or `owasp/modsecurity-crs:apache`. If you need a stable long term image, use the one with the full CRS version, in addition to the build date in `YYYYMMDDHHMM` format, example `owasp/modsecurity-crs:3.3.5-nginx-202209141209` or `owasp/modsecurity-crs:3.3.5-apache-202209141209` for example. You have been warned.

🆕 We added healthchecks to the images. Containers already return HTTP status code 200 when accessing the `/healthz` URI. When a container has a healthcheck specified, it has a _health status_ in addition to its normal status. This status is initially `starting`. Whenever a health check passes, it becomes `healthy` (whatever state it was previously in). After a certain number of consecutive failures, it becomes `unhealthy`. See <https://docs.docker.com/engine/reference/builder/#healthcheck> for more information.

## Supported variants

We also build [alpine linux](https://www.alpinelinux.org/) variants of the base images, using the `-alpine` suffix. Examples:

* `3-nginx-alpine-YYYYMMDDHHMM`, `3.3-nginx-alpine-YYYYMMDDHHMM`, `3.3.5-nginx-alpine-YYYYMMDDHHMM`, `nginx-alpine` ([master/nginx/Dockerfile-alpine](https://github.com/coreruleset/modsecurity-crs-docker/blob/master/nginx/Dockerfile-alpine) – *last stable ModSecurity v3 on Nginx 1.24 official alpine stable base image, and latest stable Core Rule Set 3.3.5*
* `3-apache-alpine-YYYYMMDDHHMM`, `3.3-apache-alpine-YYYYMMDDHHMM`, `3.3.5-apache-alpine-YYYYMMDDHHMM`, `apache-alpine` ([master/apache/Dockerfile-alpine](https://github.com/coreruleset/modsecurity-crs-docker/blob/master/apache/Dockerfile-alpine)) – *last stable ModSecurity v2 on Apache 2.4.56 official alpine stable base image, and latest stable Core Rule Set 3.3.5*

⚠️ We changed tags to [support production usage](https://github.com/coreruleset/modsecurity-crs-docker/issues/67). Now, if you want to use the "rolling version", use the tag `owasp/modsecurity-crs:nginx-alpine` or `owasp/modsecurity-crs:apache-alpine`. If you need a stable long term image, use the one with the full CRS version, in addition to the build date in `YYYYMMDDHHMM` format, example `owasp/modsecurity-crs:3.3.5-nginx-alpine-202209141209` or `owasp/modsecurity-crs:3.3.5-apache-alpine-202209141209` for example. You have been warned.

## Supported architectures

We added the [docker buildx](https://github.com/docker/buildx) support to our docker builds so additional architectures are supported now. As we create our containers based on the official apache and nginx ones, we can only support the architectures they support.

There is a new file `docker-bake.hcl` used for this purpose. To build for new platforms, just use this example:

```bash
docker buildx create --use --platform linux/amd64,linux/i386,linux/arm64,linux/arm/v7
docker buildx bake -f docker-bake.hcl
```

We require a version of `buildx` >= v0.9.1. [Visit the official documentation](https://docs.docker.com/build/buildx/install/) for instructions on installing and upgrading `buildx`. You can check which version you have using:

```bash
docker buildx version
github.com/docker/buildx v0.9.1 ed00243a0ce2a0aee75311b06e32d33b44729689
```

If you want to see the targets of the build, use:

```bash
docker buildx bake -f ./docker-bake.hcl --print
```

We are building now for these architectures:

* linux/amd64
* linux/i386
* linux/arm64
* linux/arm/v7

You can find additional examples on how to use `buildx` in this repository's GitHub act
We added the [docker buildx](https://github.com/docker/buildx) support to our docker builds so additional architectures are supported now. As we create our containers based on the official apache and nginx ones, we can only support the architectures they support.

To build a specific target for a single platform only (replace target and platform strings in the example with the your choices):

```bash
docker buildx bake -f docker-bake.hcl --set target.platforms=linux/amd64 nginx-alpine
```

## CRS Versions

> Hey, I used some specific git version with the containers? What happened?

You can achieve the same results just by getting any version you want, and using docker volumes. See this example:

```bash
git clone https://github.com/coreruleset/coreruleset.git myrules
cd myrules
git checkout ac2a0d1
docker run -p 80:80 -ti -e PARANOIA=4 -v rules:/opt/owasp-crs/rules:ro --rm owasp/modsecurity-crs
```

## Quick reference

* **Where to get help**: the [CRS-Support Docker Repo](https://github.com/coreruleset/modsecurity-crs-docker), the [Core Rule Set Slack Channel](https://owasp.org/slack/invite) (#coreruleset on owasp.slack.com), or [Stack Overflow](https://stackoverflow.com/questions/tagged/mod-security)

* **Where to file issues**: the [Core Rule Set Docker Repo](https://github.com/coreruleset/modsecurity-crs-docker)

* **Maintained By**: The Core Rule Set Project maintainers

## What is ModSecurity

ModSecurity is an open source, cross platform Web Application Firewall (WAF) engine for Apache, IIS and Nginx. It has a robust event-based programming language which provides protection from a range of attacks against web applications and allows for HTTP traffic monitoring, logging and real-time analysis.

### Nginx based images breaking change

| ⚠️ WARNING          |
|:---------------------------|
| Nginx based images are now based on upstream nginx. This changed the way the config file for nginx is generated.  |

If using the [Nginx environment variables](https://github.com/coreruleset/modsecurity-crs-docker#nginx-env-variables) is not enough for your use case, you can mount your own `nginx.conf` file as the new template for generating the base config.

An example can be seen in the [docker-compose](https://github.com/coreruleset/modsecurity-crs-docker/blob/master/docker-compose.yml) file.

> 💬 What happens if I want to make changes in a different file, like `/etc/nginx/conf.d/default.conf`?
> You mount your local file, e.g. `nginx/default.conf` as the new template: `/etc/nginx/templates/conf.d/default.conf.template`. You can do this similarly with other files. Files in the templates directory will be copied and subdirectories will be preserved.

### TLS/HTTPS

TLS is configured by default on port 443. Note: The default configuration generates a self signed certificate on first run. To use your own certificates (recommended) `COPY` or mount (`-v`) your `server.crt` and `server.key` into `/usr/local/apache2/conf/` or `/etc/nginx/conf/`. Remember to publish the HTTPS port when running the image.

```bash
docker build -t my-modsec .
docker run -p 8443:443 my-modsec
```

We use sane intermediate defaults taken from the [Mozilla SSL config tool](https://ssl-config.mozilla.org/). Please check it and choose the best that match your needs.

You can use variables on nginx and apache to always redirect from http to https if needed (see APACHE_ALWAYS_TLS_REDIRECT and NGINX_ALWAYS_TLS_REDIRECT below).

### Proxying

ModSecurity is often used as a reverse proxy. This allows one to use ModSecurity without modifying the webserver hosting the underlying application (and also protect web servers that modsecurity cannot currently embedd into). The proxy is set by default to true and the location is defined by BACKEND environment variable. The SSL is enabled by default.

```bash
docker build -t my-modsec . -f
docker run -p 8080:80 -e PROXY_SSL=on -e BACKEND=http://example.com my-modsec
```

### ServerName

It is often convenient to set your servername. To do this simply use the `SERVER_NAME` environment variable passed to docker run. By default the servername provided is `localhost`.

```bash
docker build -t modsec .
docker run -p 8080:80 -e SERVER_NAME=myhost my-modsec
```

### Apache ENV Variables

| Name     | Description|
| -------- | ------------------------------------------------------------------- |
| ACCESSLOG | A string value indicating the location of the custom log file (Default: `/var/log/apache2/access.log`) |
| APACHE_ALWAYS_TLS_REDIRECT | A string value indicating if http should redirect to https (Allowed values: `on`, `off`. Default: `off`) |
| APACHE_LOGFORMAT | A string value indicating the LogFormat that apache should use. (Default: `'"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\""'` (combined). Tip: use single quotes outside your double quoted format string.) ⚠️ Do not add a `|` as part of the log format. It is used internally.  |
| APACHE_ERRORLOG_FORMAT | A string value indicating the `ErrorLogFormat` that Apache should use. (Default: `'"[%{u}t] [%-m:%l] [pid %P:tid %T] %7F: %E: [client\ %a] %M% ,\ referer\ %{Referer}i"'` |
| APACHE_METRICS_LOGFORMAT | A string value indicating the LogFormat that the additional log apache metrics should use. (Default:'"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\""' (combined). Tip: use single quotes outside your double quoted format string.) ⚠️ Do not add a `|` as part of the log format. It is used internally.  |
| BACKEND | A string indicating the partial URL for the remote server of the `ProxyPass` directive (Default: `http://localhost:80`) |
| BACKEND_WS | A string indicating the IP/URL of the WebSocket service (Default: `ws://localhost:8080`) |
| ERRORLOG  | A string value indicating the location of the error log file (Default: `/var/log/apache2/error.log`) |
| H2_PROTOCOLS  | A string value indicating the protocols supported by the HTTP2 module (Default: `h2 http/1.1`) |
| LOGLEVEL  | A string value controlling the number of messages logged to the error_log (Default: `warn`) |
| METRICS_ALLOW_FROM  | A string indicating a range of IP adresses that can access the metrics (Default: `127.0.0.0/255.0.0.0 ::1/128`) |
| METRICS_DENY_FROM  | A string indicating a range of IP adresses that cannot access the metrics (Default: `All`) |
| METRICSLOG  | A string indicating the path of the metrics log (Default: `/dev/null`) |
| MUTEX | Configure mutex and lock file directory for all specified mutexes (see [Mutex](https://httpd.apache.org/docs/2.4/mod/core.html#mutex)) (Default: `default`) |
| PORT  | An integer value indicating the port where the webserver is listening to (Default: `80`) |
| PROXY_ERROR_OVERRIDE  | A string indicating that errors from the backend services should be overridden by this proxy server (see [ProxyErrorOverride](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html#proxyerroroverride) directive). (Allowed values: `on`, `off`. Default: `on`) |
| PROXY_PRESERVE_HOST  | A string indicating the use of incoming Host HTTP request header for proxy request (Default: `on`) |
| PROXY_SSL_CERT_KEY  | A string indicating the path to the server PEM-encoded private key file (Default: `/usr/local/apache2/conf/server.key`) |
| PROXY_SSL_CERT  | A string indicating the path to the server PEM-encoded X.509 certificate data file or token identifier (Default: `/usr/local/apache2/conf/server.crt`) |
| PROXY_SSL_CHECK_PEER_NAME  | A string indicating if the host name checking for remote server certificates is to be enabled (Default: `on`) |
| PROXY_SSL_VERIFY  | A string value indicating the type of remote server Certificate verification (Default: `none`) |
| PROXY_SSL  | A string indicating SSL Proxy Engine Operation Switch (Default: `off`) |
| PROXY_TIMEOUT  | Number of seconds for proxied requests to time out (Default: `60`) |
| REMOTEIP_INT_PROXY  | A string indicating the client intranet IP addresses trusted to present the RemoteIPHeader value (Default: `10.1.0.0/16`) |
| REQ_HEADER_FORWARDED_PROTO  | A string indicating the transfer protocol of the initial request (Default: `https`) |
| SERVER_ADMIN  | A string value indicating the address where problems with the server should be e-mailed (Default: `root@localhost`) |
| SERVER_NAME | A string value indicating the server name (Default: `localhost`) |
| SSL_CIPHER_SUITE | A string indicating the cipher suite to use. Uses OpenSSL [list of cipher suites](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_ciphersuites.html) (Default: `"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"` |
| SSL_ENGINE  | A string indicating the SSL Engine Operation Switch (Default: `on`) |
| SSL_HONOR_CIPHER_ORDER | A string indicating if the server should [honor the cipher list provided by the client](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslhonorcipherorder) (Allowed values: `on`, `off`. Default: `off`) |
| SSL_PORT  | Port number where the SSL enabled webserver is listening (Default: `443`) |
| SSL_PROTOCOL | A string for configuring the [usable SSL/TLS protocol versions](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslprotocol) (Default: `"all -SSLv3 -TLSv1 -TLSv1.1"`) |
| SSL_PROXY_PROTOCOL | A string for configuring the [proxy client SSL/TLS protocol versions](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslproxyprotocol) (Default: `"all -SSLv3 -TLSv1 -TLSv1.1"`) |
| SSL_PROXY_CIPHER_SUITE | A string indicating the cipher suite to connect to the backend via TLS. (Default `"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"` |
| SSL_SESSION_TICKETS | A string to enable or disable the use of [TLS session tickets](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslsessiontickets) (RFC 5077). (Default: `off`) |
| SSL_USE_STAPLING | A string indicating if [OSCP Stapling](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslusestapling) should be used (Allowed values: `on`, `off`. Default: `on`) |
| TIMEOUT  | Number of seconds before receiving and sending timeout (Default: `60`) |
| WORKER_CONNECTIONS  | Maximum number of MPM request worker processes (Default: `400`) |

Note: Apache access and metric logs can be disabled by exporting the `nologging=1` environment variable, or using `ACCESSLOG=/dev/null` and `METRICSLOG=/dev/null`.

### Nginx ENV Variables

| Name     | Description|
| -------- | ------------------------------------------------------------------- |
| ACCESSLOG  | A string value indicating the location of the access log file (Default: `/var/log/nginx/access.log`) |
| BACKEND  | A string indicating the partial URL for the remote server of the `proxy_pass` directive (Default: `http://localhost:80`) |
| DNS_SERVER  | A string indicating the name servers used to resolve names of upstream servers into addresses. For localhost backend this value should not be defined (Default: _not defined_) |
| ERRORLOG  | A string value indicating the location of the error log file (Default: `/proc/self/fd/2`) |
| LOGLEVEL  | A string value controlling the number of messages logged to the error_log (Default: `warn`) |
| METRICS_ALLOW_FROM  | A string indicating a single range of IP adresses that can access the metrics (Default: `127.0.0.0/24`) |
| METRICS_DENY_FROM  | A string indicating a range of IP adresses that cannot access the metrics (Default: `all`) |
| METRICSLOG  | A string value indicating the location of metrics log file (Default: `/dev/null`) |
| NGINX_ALWAYS_TLS_REDIRECT | A string value indicating if http should redirect to https (Allowed values: `on`, `off`. Default: `off`) |
| PORT  | An integer value indicating the port where the webserver is listening to (Default: `80`) |
| SET_REAL_IP_FROM | A string of comma separated IP, CIDR, or UNIX domain socket addresses that are trusted to replace addresses in `REAL_IP_HEADER` (Default: `127.0.0.1`). See [set_real_ip_from](http://nginx.org/en/docs/http/ngx_http_realip_module.html#set_real_ip_from) |
| REAL_IP_HEADER | Name of the header containing the real IP value(s) (Default: `X-REAL-IP`). See [real_ip_header](http://nginx.org/en/docs/http/ngx_http_realip_module.html#real_ip_header) |
| REAL_IP_PROXY_HEADER | Name of the header containing `$remote_addr` to be passed to proxy (Default: `X-REAL-IP`). See [proxy_set_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header) |
| REAL_IP_RECURSIVE | A string value indicating whether to use recursive reaplacement on addresses in `REAL_IP_HEADER` (Allowed values: `on`, `off`. Default: `on`). See [real_ip_recursive](http://nginx.org/en/docs/http/ngx_http_realip_module.html#real_ip_recursive) |
| PROXY_SSL_CERT  | A string value indicating the path to the server PEM-encoded X.509 certificate data file or token value identifier (Default: `/etc/nginx/conf/server.crt`) |
| PROXY_SSL_CERT_KEY  | A string value indicating the path to the server PEM-encoded private key file (Default: `/etc/nginx/conf/server.key`) |
| PROXY_SSL_CIPHERS | A String value indicating the enabled ciphers. The ciphers are specified in the format understood by the OpenSSL library. (Default: `ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;`|
| PROXY_SSL_DH_BITS | A numeric value indicating the size (in bits) to use for the generated DH-params file (Default 2048) |
| PROXY_SSL_OCSP_STAPLING | A string value indicating if ssl_stapling and ssl_stapling_verify should be enabled (Allowed values: `on`, `off`. Default: `off`) |
| PROXY_SSL_PREFER_CIPHERS | A string value indicating if the server ciphers should be preferred over client ciphers when using the SSLv3 and TLS protocols (Allowed values: `on`, `off`. Default: `off`)|
| PROXY_SSL_PROTOCOLS | A string value indicating the ssl protocols to enable (default: `TTLSv1.2 TLSv1.3`)|
| PROXY_SSL_VERIFY  | A string value indicating if the client certificates should be verified (Allowed values: `on`, `off`. Default: `off`) |
| PROXY_TIMEOUT  | Number of seconds for proxied requests to time out connections (Default: `60s`) |
| SSL_PORT  | Port number where the SSL enabled webserver is listening (Default: `443`) |
| TIMEOUT  | Number of seconds for a keep-alive client connection to stay open on the server side (Default: `60s`) |
| WORKER_CONNECTIONS  | Maximum number of simultaneous connections that can be opened by a worker process (Default: `1024`) |

### ModSecurity ENV Variables

All these variables impact in configuration directives in the modsecurity engine running inside the container. The [reference manual](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)) has the extended documentation, and for your reference we list the specific directive we change when you modify the ENV variables for the container.

| Name     | Description|
| -------- | ------------------------------------------------------------------- |
| MODSEC_AUDIT_ENGINE  | A string used to configure the audit engine, which logs complete transactions (Default: `RelevantOnly`). Accepted values: `On`, `Off`, `RelevantOnly`. See [SecAuditEngine](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#SecAuditEngine) for additional information. |
| MODSEC_AUDIT_LOG  | A string indicating the path to the main audit log file or the concurrent logging index file (Default: `/dev/stdout`) |
| MODSEC_AUDIT_LOG_FORMAT  | A string indicating the output format of the AuditLogs (Default: `JSON`). Accepted values: `JSON`, `Native`. See [SecAuditLogFormat](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#SecAuditLogFormat) for additional information. |
| MODSEC_AUDIT_LOG_TYPE  | A string indicating the type of audit logging mechanism to be used (Default: `Serial`). Accepted values: `Serial`, `Concurrent` (`HTTPS` works only on Nginx - v3). See [SecAuditLogType](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#secauditlogtype) for additional information. |
| MODSEC_AUDIT_LOG_PARTS  | A string that defines which parts of each transaction are going to be recorded in the audit log (Default: `'ABIJDEFHZ'`). See [SecAuditLogParts](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#secauditlogparts) for the accepted values. |
| MODSEC_AUDIT_STORAGE  | A string indicating the directory where concurrent audit log entries are to be stored (Default: `/var/log/modsecurity/audit/`) |
| MODSEC_DATA_DIR  | A string indicating the path where persistent data (e.g., IP address data, session data, and so on) is to be stored (Default: `/tmp/modsecurity/data`) |
| MODSEC_DEBUG_LOG  | A string indicating the path to the ModSecurity debug log file (Default: `/dev/null`) |
| MODSEC_DEBUG_LOGLEVEL  | An integer indicating the verboseness of the debug log data (Default: `0`). Accepted values: `0` - `9`. See [SecDebugLogLevel](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#secdebugloglevel). |
| MODSEC_DISABLE_BACKEND_COMPRESSION  | A string indicating whether or not to disable backend compression (Default: `On`). Allowed values: `On`, `Off`. See [SecDisableBackendCompression](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#secdisablebackendcompression) for more. Only supported in ModSecurity 2.x, will have not effect on 3.x |
| MODSEC_PCRE_MATCH_LIMIT  | An integer value indicating the limit for the number of internal executions in the PCRE function (Default: `100000`) (Only valid for Apache - v2). See [SecPcreMatchLimit](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#SecPcreMatchLimit) |
| MODSEC_PCRE_MATCH_LIMIT_RECURSION  | An integer value indicating the limit for the depth of recursion when calling PCRE function (Default: `100000`) |
| MODSEC_REQ_BODY_ACCESS  | A string value allowing ModSecurity to access request bodies (Default: `On`). Allowed values: `On`, `Off`. See [SecRequestBodyAccess](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#secrequestbodyaccess) for more information. |
| MODSEC_REQ_BODY_LIMIT  | An integer value indicating the maximum request body size  accepted for buffering (Default: `13107200`). See [SecRequestBodyLimit](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#secrequestbodylimit) for additional information. |
| MODSEC_REQ_BODY_LIMIT_ACTION  | A string value for the action when `SecRequestBodyLimit` is reached (Default: `Reject`). Accepted values: `Reject`, `ProcessPartial`. See [SecRequestBodyLimitAction](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#secrequestbodylimitaction) for additional information. |
| MODSEC_REQ_BODY_JSON_DEPTH_LIMIT | An integer value indicating the maximun JSON request depth (Default: `512`). See [SecRequestBodyJsonDepthLimit](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#SecRequestBodyJsonDepthLimit) for additional information. |
| MODSEC_REQ_BODY_NOFILES_LIMIT  | An integer indicating the maximum request body size ModSecurity will accept for buffering (Default: `131072`). See [SecRequestBodyNoFilesLimit](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#secrequestbodynofileslimit) for more information. |
| MODSEC_RESP_BODY_ACCESS  | A string value allowing ModSecurity to access response bodies (Default: `On`). Allowed values: `On`, `Off`. See [SecResponseBodyAccess](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#secresponsebodyaccess) for more information. |
| MODSEC_RESP_BODY_LIMIT  | An integer value indicating the maximum response body size accepted for buffering (Default: `1048576`) |
| MODSEC_RESP_BODY_LIMIT_ACTION  | A string value for the action when `SecResponseBodyLimit` is reached (Default: `ProcessPartial`). Accepted values: `Reject`, `ProcessPartial`. See [SecResponseBodyLimitAction](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#secresponsebodylimitaction) for additional information. |
| MODSEC_RESP_BODY_MIMETYPE  | A string with the list of mime types that will be analyzed in the response (Default: `'text/plain text/html text/xml'`). You might consider adding `application/json` documented [here](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-\(v2.x\)#secresponsebodymimetype). |
| MODSEC_RULE_ENGINE  | A string value enabling ModSecurity itself (Default: `On`). Accepted values: `On`, `Off`, `DetectionOnly`. See [SecRuleEngine](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#secruleengine) for additional information. |
| MODSEC_STATUS_ENGINE  | A string used to configure the status engine, which sends statistical information (Default: `Off`). Accepted values: `On`, `Off`. See [SecStatusEngine](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#SecStatusEngine) for additional information. |
| MODSEC_TAG  | A string indicating the default tag action, which will be inherited by the rules in the same configuration context (Default: `modsecurity`) |
| MODSEC_TMP_DIR  | A string indicating the path where temporary files will be created (Default: `/tmp/modsecurity/tmp`) |
| MODSEC_TMP_SAVE_UPLOADED_FILES  | A string indicating if temporary uploaded files are saved (Default: `On`) (only relevant in Apache - ModSecurity v2) |
| MODSEC_UPLOAD_DIR  | A string indicating the path where intercepted files will be stored (Default: `/tmp/modsecurity/upload`) |
| MODSEC_DEFAULT_PHASE1_ACTION | ModSecurity string with the contents for the default action in phase 1 (Default: `'phase:1,log,auditlog,pass,tag:\'\${MODSEC_TAG}\''`) |
| MODSEC_DEFAULT_PHASE2_ACTION | ModSecurity string with the contents for the default action in phase 2 (Default: `'phase:2,log,auditlog,pass,tag:\'\${MODSEC_TAG}\''`) |

### Overridden

| Name     | Description|
| -------- | ------------------------------------------------------------------- |
| USER | A string value indicating the name (or #number) of the user to run httpd or nginx as (Default: `www-data` (httpd), `nginx` (nginx)) |
| GROUP | A string value indicating the name (or #number) of the group to run httpd as (Default: `www-data`) |
| BACKEND  | The backend address (and optional port) of the backend server. (Default: the container's default router, port 81) (Examples: 192.0.2.2, 192.0.2.2:80, <http://172.17.0.1:8000>) |

### CRS specific

| Name     | Description|
| -------- | ------------------------------------------------------------------- |
| MANUAL_MODE | A boolean indicating that you are providing your own `crs-setup.conf` file mounted as volume. (Default: `0`). ⚠️ None of the following variables are used if you set it to `1`. |
| CRS_DISABLE_PLUGINS | A boolean indicating whether plugins will be **disabled** (Only from v4 and up. Default: `0`) |
| PARANOIA | An integer indicating the paranoia level (Default: `1`)               |
| BLOCKING_PARANOIA | (:new: Replaces `PARANOIA` in CRSv4) An integer indicating the paranoia level (Default: `1`)               |
| EXECUTING_PARANOIA | An integer indicating the executing_paranoia_level (Default: `PARANOIA`) |
| DETECTION_PARANOIA | (:new: Replaces `EXECUTING_PARANOIA` in CRSv4) An integer indicating the detection_paranoia_level (Default: `BLOCKING_PARANOIA`) |
| ENFORCE_BODYPROC_URLENCODED | A boolean indicating the enforce_bodyproc_urlencoded (Default: `0`) |
| VALIDATE_UTF8_ENCODING | A boolean indicating the crs_validate_utf8_encoding (Default: `0`) |
| ANOMALY_INBOUND | An integer indicating the inbound_anomaly_score_threshold (Default: `5`) |
| ANOMALY_OUTBOUND | An integer indicating the outbound_anomaly_score_threshold (Default: `4`) |
| ALLOWED_METHODS | A string indicating the allowed_methods (Default: `GET HEAD POST OPTIONS`) |
| ALLOWED_REQUEST_CONTENT_TYPE | A string indicating the allowed_request_content_type (Default: `\|application/x-www-form-urlencoded\| \|multipart/form-data\| \|multipart/related\| \|text/xml\| \|application/xml\| \|application/soap+xml\| \|application/json\| \|application/cloudevents+json\| \|application/cloudevents-batch+json\|`) |
| ALLOWED_REQUEST_CONTENT_TYPE_CHARSET | A string indicating the allowed_request_content_type_charset (Default: `utf-8\|iso-8859-1\|iso-8859-15\|windows-1252`) |
| ALLOWED_HTTP_VERSIONS | A string indicating the allowed_http_versions (Default: `HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0`) |
| RESTRICTED_EXTENSIONS | A string indicating the restricted_extensions (Default: `.asa/ .asax/ .ascx/ .axd/ .backup/ .bak/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .com/ .config/ .conf/ .cs/ .csproj/ .csr/ .dat/ .db/ .dbf/ .dll/ .dos/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .ini/ .key/ .licx/ .lnk/ .log/ .mdb/ .old/ .pass/ .pdb/ .pol/ .printer/ .pwd/ .rdb/ .resources/ .resx/ .sql/ .swp/ .sys/ .vb/ .vbs/ .vbproj/ .vsdisco/ .webinfo/ .xsd/ .xsx/`) |
| RESTRICTED_HEADERS | A string indicating the restricted_headers (Default: `/accept-charset/ /content-encoding/ /proxy/ /lock-token/ /content-range/ /if/`) |
| STATIC_EXTENSIONS | A string indicating the static_extensions (Default: `/.jpg/ /.jpeg/ /.png/ /.gif/ /.js/ /.css/ /.ico/ /.svg/ /.webp/`) |
| MAX_NUM_ARGS | An integer indicating the max_num_args (Default: `unlimited`) |
| ARG_NAME_LENGTH | An integer indicating the arg_name_length (Default: `unlimited`) |
| ARG_LENGTH | An integer indicating the arg_length (Default: `unlimited`) |
| TOTAL_ARG_LENGTH | An integer indicating the total_arg_length (Default: `unlimited`) |
| MAX_FILE_SIZE | An integer indicating the max_file_size (Default: `unlimited`) |
| COMBINED_FILE_SIZES | An integer indicating the combined_file_sizes (Default: `unlimited`) |
| CRS_ENABLE_TEST_MARKER | A boolean indicating whether to write test markers to the log file (Used for running the CRS test suite. Default: `0`) |

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

```bash
docker run -dti --rm \
   -p 80:80 \
   -v /path/to/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf:/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf \
   -v /path/to/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf:/etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf \
   owasp/modsecurity-crs:apache
```

### Copy ModSecurity tuning file into created container

This example can be helpful when no volume mounts are possible (some CI pipelines).

```bash
docker create -ti --name modseccrs \
   -p 80:80 \
   owasp/modsecurity-crs:apache

docker cp /path/to/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf \
   modseccrs:/etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf

docker start modseccrs
```

## Full docker run example of possible setup

```bash
docker run -dti -p 80:80 --rm \
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
   -e SERVER_ADMIN=root@localhost \
   -e SERVER_NAME=localhost \
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
   -e CRS_ENABLE_TEST_MARKER=1 \
   owasp/modsecurity-crs:apache
```
