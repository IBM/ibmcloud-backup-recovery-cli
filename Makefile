# Makefile to build the project
GO=go
LINT=golangci-lint
GOSEC=gosec
SCANOPTS=

COVERAGE = -coverprofile=coverage.txt -covermode=atomic

all: tidy install-plugin

# The code can compile/test fine but be invalid for the ibmcloud cli framework.
# Verify the plugin can be installed with the framework with the install-plugin target
# and execute the "scripts" to ensure there are no issues with running them.
travis-ci: tidy install-plugin binaries checksums

build:
	${GO} build main.go

install:
	ibmcloud plugin install main -f

install-plugin: build install

tidy:
	${GO} mod tidy

# Convenience "make" targets for the files in the "scripts" directory.

translations:
	./scripts/prepare-translations.sh

binaries:
	./scripts/generate-binaries.sh

checksums:
	./scripts/print-checksums.sh
