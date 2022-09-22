# docker-bake.hcl
variable "crs-version" {
    default = "3.3.4"
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
        tag("${major(semver)}${variant}-${formatdate("YYYYMMDDHHMM", timestamp())}"),
        tag("${minor(semver)}${variant}-${formatdate("YYYYMMDDHHMM", timestamp())}"),
        tag("${patch(semver)}${variant}-${formatdate("YYYYMMDDHHMM", timestamp())}")
    )
}

group "default" {
    targets = [
        "apache",
        "apache-alpine",
        "nginx",
        "nginx-alpine"
    ]
}

target "docker-metadata-action" {}

target "platforms-base" {
    inherits = ["docker-metadata-action"]
    context="."    
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v7", "linux/i386"]
    args = {
        RELEASE = "${crs-version}"
    }
}

target "apache" {
    inherits = ["platforms-base"]
    dockerfile="apache/Dockerfile"
    tags = concat(tag("apache"),
        vtag("${crs-version}", "-apache")
    )
}

target "apache-alpine" {
    inherits = ["platforms-base"]
    dockerfile="apache/Dockerfile-alpine"
    tags = concat(tag("apache-alpine"),
        vtag("${crs-version}", "-apache-alpine")
    )
}

target "nginx" {
    inherits = ["platforms-base"]
    dockerfile="nginx/Dockerfile"
    tags = concat(tag("nginx"),
        vtag("${crs-version}", "-nginx")
    )
}

target "nginx-alpine" {
    inherits = ["platforms-base"]
    dockerfile="nginx/Dockerfile-alpine"
    tags = concat(tag("nginx-alpine"),
        vtag("${crs-version}", "-nginx-alpine")
    )
}
