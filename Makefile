# Makefile to build the project
GO=go
LINT=golangci-lint
GOSEC=gosec
SCANOPTS=

COVERAGE = -coverprofile=coverage.txt -covermode=atomic

all: tidy test install-plugin lint sec

# The code can compile/test fine but be invalid for the ibmcloud cli framework.
# Verify the plugin can be installed with the framework with the install-plugin target
# and execute the "scripts" to ensure there are no issues with running them.
travis-ci: tidy test-cov install-plugin lint sec binaries checksums

test:
	${GO} test ./...

test-cov:
	${GO} test ./... ${COVERAGE}

build:
	${GO} build main.go

install:
	ibmcloud plugin install main -f

install-plugin: build install

lint:
	${LINT} run

sec:
	${GOSEC} ${SCANOPTS} ./...

tidy:
	${GO} mod tidy

# Convenience "make" targets for the files in the "scripts" directory.

translations:
	./scripts/prepare-translations.sh

binaries:
	./scripts/generate-binaries.sh

checksums:
	./scripts/print-checksums.sh
