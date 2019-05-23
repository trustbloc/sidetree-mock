#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

#
# Supported Targets:
#
#   all (default) : runs code checks, unit and integration tests
#   checks: runs code checks (license, lint)
#   unit-test: runs unit tests
#   generate: generates Go Swagger artifacts

GO_CMD ?= go
export GO111MODULE=on

checks: generate license lint

license:
	@scripts/check_license.sh

lint:
	@scripts/check_lint.sh

generate: clean
		@scripts/generate.sh

unit-test:
	@scripts/unit.sh

all: clean checks unit-test

clean:
	rm -Rf ./build
	rm -Rf ./cmd/
	rm -Rf ./models/
	rm -Rf ./restapi/operations/
	rm -Rf ./restapi/doc.go
	rm -Rf ./restapi/embedded_spec.go
	rm -Rf ./restapi/server.go





