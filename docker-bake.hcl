# docker-bake.hcl
variable "modsec3-version" {
    # renovate: depName=ModSecurity3 packageName=owasp-modsecurity/ModSecurity datasource=github-releases
    default = "3.0.13"
}

variable "modsec2-version" {
    # renovate: depName=ModSecurity2 packageName=owasp-modsecurity/ModSecurity datasource=github-releases
    default = "2.9.8"
}

variable "crs-version" {
    # renovate: depName=coreruleset/coreruleset datasource=github-releases
    default = "4.9.0"
}

variable "nginx-version" {
    # renovate: depName=nginxinc/nginx-unprivileged datasource=docker
    default = "1.27.3"
}

variable "httpd-version" {
    # renovate: depName=httpd datasource=docker
    default = "2.4.62"
}

variable "lua-version" {
    default = "5.3"
}

variable "lmdb-version" {
    default = "0.9.29"
}


variable "lua-modules-alpine" {
  default = [
    "lua-lzlib",
    "lua-socket"
  ]
}

variable "lua-modules-debian" {
  default = [
    "lua-zlib",
    "lua-socket"
  ]
}

variable "REPOS" {
    # List of repositories to tag
    default = [
        "owasp/modsecurity-crs",
        "ghcr.io/coreruleset/modsecurity-crs",
    ]
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
    result = [for repo in REPOS : "${repo}:${tag}"]
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
        LUA_MODULES = join(" ", lua-modules-debian)
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
        LUA_MODULES = join(" ", lua-modules-alpine)
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
        LUA_MODULES = join(" ", lua-modules-debian)
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
        LUA_MODULES = join(" ", lua-modules-alpine)
    }
    tags = concat(tag("nginx-alpine"),
        vtag("${crs-version}", "nginx-alpine")
    )
}

