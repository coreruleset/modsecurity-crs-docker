# docker-bake.hcl
variable "modsec3-version" {
    # renovate: depName=ModSecurity3 packageName=owasp-modsecurity/ModSecurity datasource=github-releases
    default = "3.0.14"
}

variable "modsec3-flags" {
    default = "--with-yajl --with-ssdeep --with-lmdb --with-pcre2 --with-maxmind --enable-silent-rules"
}

variable "modsec2-version" {
    # renovate: depName=ModSecurity2 packageName=owasp-modsecurity/ModSecurity datasource=github-releases
    default = "2.9.10"
}

variable "modsec2-flags" {
    default = "--with-yajl --with-ssdeep --with-pcre2"
}

variable "crs-version" {
    # renovate: depName=coreruleset/coreruleset datasource=github-releases
    default = "4.15.0"
}

variable "nginx-version" {
    # renovate: depName=nginxinc/nginx-unprivileged datasource=docker
    default = "1.28.0"
}

variable "httpd-version" {
    # renovate: depName=httpd datasource=docker
    default = "2.4.63"
}

variable "modsecurity-nginx-version" {
    default = "1.0.4"
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
    default = "owasp/modsecurity-crs, ghcr.io/coreruleset/modsecurity-crs"
}

variable "nginx-dynamic-modules" {
    # List of dynamic modules to include in the nginx build
    default = [
        {owner: "owasp-modsecurity", name: "ModSecurity-nginx", version: "v${modsecurity-nginx-version}"},
        {owner: "openresty", name: "headers-more-nginx-module", version: "master"}
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
    result = [for repo in split(",", REPOS) : "${trimspace(repo)}:${tag}"]
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
        "nginx"
    ]
}

target "platforms-base" {
    context="."
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v7", "linux/i386"]
    labels = {
        "org.opencontainers.image.source" = "https://github.com/coreruleset/modsecurity-crs-docker"
    }
    args = {
        CRS_RELEASE = "${crs-version}"
        MODSEC2_VERSION = "${modsec2-version}"
        MODSEC2_FLAGS = modsec2-flags
        MODSEC3_VERSION = "${modsec3-version}"
        MODSEC3_FLAGS = modsec3-flags
        LUA_VERSION = "${lua-version}"
        LMDB_VERSION = "${lmdb-version}"
    }
}

target "apache" {
    matrix = {
        base = [
            {
                name = "debian"
                dockerfile="apache/Dockerfile"
                image = "docker-image://httpd:${httpd-version}"
                lua_modules = join(" ", lua-modules-debian)
                tag_base = "apache"
            },
            {
                name = "alpine"
                dockerfile = "apache/Dockerfile-alpine"
                image = "docker-image://httpd:${httpd-version}-alpine"
                lua_modules = join(" ", lua-modules-alpine)
                tag_base = "apache-alpine"
            }
        ]
    }

    inherits = ["platforms-base"]
    name = "apache-${base.name}"
    contexts = {
        image = base.image
    }
    dockerfile = base.dockerfile
    args = {
        LUA_MODULES = base.lua_modules
    }
    tags = concat(tag(base.tag_base),
        vtag("${crs-version}", base.tag_base)
    )
}

target "nginx" {
    matrix = {
        base = [
            {
                name = "debian"
                dockerfile = "nginx/Dockerfile"
                image = "docker-image://nginxinc/nginx-unprivileged:${nginx-version}"
                lua_modules = join(" ", lua-modules-debian)
                tag_base = "nginx"
            },
            {
                name = "alpine"
                dockerfile = "nginx/Dockerfile-alpine"
                image = "docker-image://nginxinc/nginx-unprivileged:${nginx-version}-alpine"
                lua_modules = join(" ", lua-modules-alpine)
                tag_base = "nginx-alpine"
            }
        ],
        read-only-fs = [
            {
                name = "writable"
                read-only = "false"
            },
            # {
            #     name = "read-only"
            #     read-only = "true"
            # }
        ]
    }
    inherits = ["platforms-base"]
    name = "nginx-${base.name}-${read-only-fs.name}"
    contexts = {
        image = base.image
    }
    dockerfile = base.dockerfile
    args = {
        NGINX_VERSION = nginx-version
        LUA_MODULES = base.lua_modules
        NGINX_DYNAMIC_MODULES = join(" ", [for mod in nginx-dynamic-modules : join(" ", [mod.owner, mod.name, mod.version])])
        NGINX_HOME = "/etc/nginx"
        READ_ONLY_FS = read-only-fs.read-only
    }
    tags = concat(tag("${base.tag_base}${equal(read-only-fs.read-only, "true") ? "-read-only" : ""}"),
        vtag("${crs-version}", "${base.tag_base}${equal(read-only-fs.read-only, "true") ? "-read-only" : ""}")
    )
}
