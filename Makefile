# A common Makefile that includes rules to be reused in different prometheus projects.
# https://github.com/prometheus/prometheus/blob/master/Makefile.common

DOCKER_ARCHS ?= amd64 armv7 arm64

include Makefile.common

DOCKER_IMAGE_NAME ?= nessus-exporter

release: clean
	promu crossbuild
	promu crossbuild tarballs
	cd .tarballs; sha256sum * > sha256sums
.PHONY: release

clean:
	rm -rf .build .tarballs nessus_exporter*
.PHONY: clean