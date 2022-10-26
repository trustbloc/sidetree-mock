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
#   bddtests:            run bddtests
#   generate-test-keys:  generate tls test keys
#


# Local variables used by makefile
CONTAINER_IDS      = $(shell docker ps -a -q)
DEV_IMAGES         = $(shell docker images dev-* -q)
ARCH               = $(shell go env GOARCH)
GO_VER             = 1.19

# Namespace for the sidetree mock node
DOCKER_OUTPUT_NS          ?= ghcr.io/trustbloc
SIDETREE_MOCK_IMAGE_NAME  ?= sidetree-mock


# Tool commands (overridable)
DOCKER_CMD ?= docker
GO_CMD     ?= go
ALPINE_VER ?= 3.15
GO_TAGS    ?=

export GO111MODULE=on

checks: license lint

license:
	@scripts/check_license.sh

lint:
	@scripts/check_lint.sh

unit-test:
	@scripts/unit.sh

all: clean checks unit-test bddtests

sidetree-mock:
	@echo "Building sidetree-mock"
	@mkdir -p ./.build/bin
	@go build -o ./.build/bin/sidetree-mock cmd/sidetree-server/main.go

sidetree-mock-docker:
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


generate-test-keys:
	@mkdir -p -p test/bddtests/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/sidetree-mock \
		--entrypoint "/opt/workspace/sidetree-mock/scripts/generate_test_keys.sh" \
		frapsoft/openssl

bddtests: generate-test-keys sidetree-mock-docker
	@scripts/integration.sh

clean:
	rm -Rf ./.build
	rm -Rf ./test/bddtests/docker-compose.log
	rm -Rf ./test/bddtests/fixtures/keys/tls
