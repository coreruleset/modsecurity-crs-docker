# OWASP CRS Container Image

[![dockeri.co](http://dockeri.co/image/owasp/modsecurity-crs)](https://hub.docker.com/r/owasp/modsecurity-crs/)

[![License](https://img.shields.io/github/license/coreruleset/modsecurity-crs-docker.svg)](https://github.com/coreruleset/modsecurity-crs-docker/blob/master/LICENSE)


⚠️ Please refer to the [documentation on GitHub](https://github.com/coreruleset/modsecurity-crs-docker/blob/master/README.md).


## Supported Tags

### Stable Tags

Stable Tags are composed of:
   * CRS version, in the fromat `<major>[.<minor>[.<patch]]`
   * web server variant
   * OS variant (optional)
   * date, in the format `YYYYMMDDHHMM`

The stable tag format is `<CRS version>-<web server>[-<os>]-<date>`.
Examples:
   * `4-nginx-202401121309`
   * `4.0-apache-alpine-202401121309`

### Rolling Tags

Rolling tags are updated whenever a new stable tag release occurs. Rolling tags can be practical but should not be used in production.

Rolling Tags are composed of:
   * web server variant
   * OS variant (optional)

The stable tag format is `<web server>[-<os>]`.
Examples:
   * `nginx`
   * `apache-alpine`
