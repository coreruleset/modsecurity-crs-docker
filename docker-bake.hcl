# docker-bake.hcl
variable "crs-version" {
    default = "3.3.2"
}

function "major" {
    params = [version]
    result = split(".", version)[0]
}

function "minor" {
    params = [version]
    result = join(".", slice(split(".", version),0,2))
}
# result = split(version, ".")[0] + "." + split(version, ".")[1] "." + split(version, ".")[2]
function "patch" {
    params = [version]
    result = join(".", slice(split(".", version),0,3))
}

group "default" {
    targets = [
        "apache",
        "apache-alpine",
        "nginx",
        "nginx-alpine"
    ]
}

target "apache" {
    context="."
    dockerfile="apache/Dockerfile"
    tags = [
        "owasp/modsecurity-crs:apache",
        "owasp/modsecurity-crs:${major(crs-version)}-apache",
        "owasp/modsecurity-crs:${minor(crs-version)}-apache",
        "owasp/modsecurity-crs:${patch(crs-version)}-apache"
    ]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v7", "linux/i386"]
    args = {
        RELEASE = "${crs-version}"
    }
}

target "apache-alpine" {
    context="."    
    dockerfile="apache/Dockerfile-alpine"
    tags = [
        "owasp/modsecurity-crs:apache-alpine",
        "owasp/modsecurity-crs:${major(crs-version)}-apache-alpine",
        "owasp/modsecurity-crs:${minor(crs-version)}-apache-alpine",
        "owasp/modsecurity-crs:${patch(crs-version)}-apache-alpine"
    ]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v7", "linux/i386"]
    args = {
        RELEASE = "${crs-version}"
    }
}

target "nginx" {
    context="."    
    dockerfile="nginx/Dockerfile"
    tags = [
        "owasp/modsecurity-crs:nginx",
        "owasp/modsecurity-crs:${major(crs-version)}-nginx",
        "owasp/modsecurity-crs:${minor(crs-version)}-nginx",
        "owasp/modsecurity-crs:${patch(crs-version)}-nginx"
    ]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v7", "linux/i386"]
    args = {
        RELEASE = "${crs-version}"
    }
}

target "nginx-alpine" {
    context="."    
    dockerfile="nginx/Dockerfile-alpine"
    tags = [
        "owasp/modsecurity-crs:nginx-alpine",
        "owasp/modsecurity-crs:${major(crs-version)}-nginx-alpine",
        "owasp/modsecurity-crs:${minor(crs-version)}-nginx-alpine",
        "owasp/modsecurity-crs:${patch(crs-version)}-nginx-alpine"
    ]
    platforms = ["linux/amd64", "linux/arm64/v8", "linux/arm/v7", "linux/i386"]
    args = {
        RELEASE = "${crs-version}"
    }
}
