VERSIONS = v3.3.2
SERVERS = apache nginx
TAG = owasp/modsecurity-crs

TARGETS = $(foreach server,$(SERVERS),$(foreach version,$(VERSIONS),$(addsuffix -$(server),$(version))))
IMAGES = $(addprefix image/, $(TARGETS))

.PHONY: clean

all: $(TARGETS) $(IMAGES)

v%: $(addsufix /Dockerfile, $(SERVERS))
	./src/release.sh "v$*"

image/%: $(TARGETS)
	docker build --tag $(TAG):$* -f $*/Dockerfile .

clean:
	rm -rfv v*
