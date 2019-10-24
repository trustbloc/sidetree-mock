#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

#
# Supported Targets:
#
#   all:                 runs code checks, unit and integration tests
#   checks:              runs code checks (license, lint)
#   unit-test:           runs unit tests
#   generate:            generates Go Swagger artifacts
#   bddtests:            run bddtests
#   generate-test-keys:  generate tls test keys
#


# Local variables used by makefile
CONTAINER_IDS      = $(shell docker ps -a -q)
DEV_IMAGES         = $(shell docker images dev-* -q)
ARCH               = $(shell go env GOARCH)
GO_VER             = $(shell grep "GO_VER" .ci-properties |cut -d'=' -f2-)

# Namespace for the sidetree node
DOCKER_OUTPUT_NS          ?= trustbloc
SIDETREE_MOCK_IMAGE_NAME  ?= sidetree-mock


# Tool commands (overridable)
DOCKER_CMD ?= docker
GO_CMD     ?= go
ALPINE_VER ?= 3.9
GO_TAGS    ?=

export GO111MODULE=on

checks: generate license lint

license:
	@scripts/check_license.sh

lint:
	@scripts/check_lint.sh

generate: clean-generate-files
		@scripts/generate.sh

unit-test:
	@scripts/unit.sh

all: clean checks unit-test bddtests

sidetree:
	@echo "Building sidetree"
	@mkdir -p ./.build/bin
	@go build -o ./.build/bin/sidetree-mock cmd/sidetree-server/main.go

sidetree-docker: sidetree
	@docker build -f ./images/sidetree-mock/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(SIDETREE_MOCK_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) \
	--build-arg GO_TAGS=$(GO_TAGS) \
	--build-arg GOPROXY=$(GOPROXY) .

clean-images:
	@echo "Stopping all containers, pruning containers and images, deleting dev images"
ifneq ($(strip $(CONTAINER_IDS)),)
	@docker stop $(CONTAINER_IDS)
endif
	@docker system prune -f
ifneq ($(strip $(DEV_IMAGES)),)
	@docker rmi $(DEV_IMAGES) -f
endif


generate-test-keys: clean
	@mkdir -p -p test/bddtests/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/go/src/github.com/trustbloc/sidetree-mock \
		--entrypoint "/opt/go/src/github.com/trustbloc/sidetree-mock/scripts/generate_test_keys.sh" \
		frapsoft/openssl

bddtests: clean clean-generate-files checks generate-test-keys sidetree-docker
	@scripts/integration.sh

clean-generate-files:
	rm -Rf ./cmd/
	rm -Rf ./models/
	rm -Rf ./restapi/operations/
	rm -Rf ./restapi/doc.go
	rm -Rf ./restapi/embedded_spec.go
	rm -Rf ./restapi/server.go

clean:
	rm -Rf ./.build
	rm -Rf ./test/bddtests/docker-compose.log
	rm -Rf ./test/bddtests/fixtures/keys/tls
