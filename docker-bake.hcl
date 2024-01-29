# docker-bake.hcl
variable "modsec3-version" {
    default = "3.0.12"
}

variable "modsec2-version" {
    default = "2.9.7"
}

variable "crs-version" {
    default = "3.3.5"
}

variable "nginx-version" {
    default = "1.25.3"
}

variable "httpd-version" {
    default = "2.4.58"
}

variable "openresty-version" {
    default = "1.25.3.1"
}

variable "lua-version" {
    default = "5.3"
}

variable "lmdb-version" {
    default = "0.9.29"
}

variable "REPO" {
    default = "owasp/modsecurity-crs"
}

function "major" {
    params = [version]
    result = split(".", version)[0]
}

function "minor" {
    params = [version]
    result = join(".", slice(split(".", version),0,2))
}

function "patch" {
    params = [version]
    result = join(".", slice(split(".", version),0,3))
}

function "tag" {
    params = [tag]
    result = ["${REPO}:${tag}"]
}

function "vtag" {
    params = [semver, variant]
    result = concat(
        tag("${major(semver)}-${variant}-${formatdate("YYYYMMDDHHMM", timestamp())}"),
        tag("${minor(semver)}-${variant}-${formatdate("YYYYMMDDHHMM", timestamp())}"),
        tag("${patch(semver)}-${variant}-${formatdate("YYYYMMDDHHMM", timestamp())}")
    )
}

group "default" {
    targets = [
        "apache",
        "apache-alpine",
        "nginx",
        "nginx-alpine",
        "openresty-alpine-fat"
    ]
}

target "docker-metadata-action" {}

target "platforms-base" {
    inherits = ["docker-metadata-action"]
    context="."    
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v7", "linux/i386"]
    labels = {
        "org.opencontainers.image.source" = "https://github.com/coreruleset/modsecurity-crs-docker"
    }
    args = {
        CRS_RELEASE = "${crs-version}"
        MODSEC2_VERSION = "${modsec2-version}"
        MODSEC3_VERSION = "${modsec3-version}"
        LUA_VERSION = "${lua-version}"
        LMDB_VERSION = "${lmdb-version}"
    }
}

target "apache" {
    inherits = ["platforms-base"]
    dockerfile="apache/Dockerfile"
    args = {
        HTTPD_VERSION = "${httpd-version}"
    }
    tags = concat(tag("apache"),
        vtag("${crs-version}", "apache")
    )
}

target "apache-alpine" {
    inherits = ["platforms-base"]
    dockerfile="apache/Dockerfile-alpine"
    args = {
        HTTPD_VERSION = "${httpd-version}"
    }
    tags = concat(tag("apache-alpine"),
        vtag("${crs-version}", "apache-alpine")
    )
}

target "nginx" {
    inherits = ["platforms-base"]
    dockerfile="nginx/Dockerfile"
    args = {
        NGINX_VERSION = "${nginx-version}"
    }
    tags = concat(tag("nginx"),
        vtag("${crs-version}", "nginx")
    )
}

target "nginx-alpine" {
    inherits = ["platforms-base"]
    dockerfile="nginx/Dockerfile-alpine"
    args = {
        NGINX_VERSION = "${nginx-version}"
    }
    tags = concat(tag("nginx-alpine"),
        vtag("${crs-version}", "nginx-alpine")
    )
}

target "openresty-alpine-fat" {
    inherits = ["platforms-base"]
    platforms = ["linux/amd64", "linux/arm64/v8"]
    dockerfile="openresty/Dockerfile-alpine"
    args = {
        OPENRESTY_VERSION = "${openresty-version}"
        NGINX_VERSION = "${nginx-version}"
    }
    tags = concat(tag("openresty-alpine-fat"),
        vtag("${crs-version}", "openresty-alpine-fat")
    )
}
