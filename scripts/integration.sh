#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running sidetree-mock integration tests..."
PWD=`pwd`
cd test/bddtests
go test -count=1 -v -cover . -p 1 -timeout=20m -race
TAGS=interop_resolve_with_initial_value,interop_create_doc go test -count=1 -v -cover . -p 1 -timeout=20m -race
TAGS=interop_recover_doc go test -count=1 -v -cover . -p 1 -timeout=20m -race
TAGS=interop_deactivate_doc go test -count=1 -v -cover . -p 1 -timeout=20m -race
TAGS=interop_update_doc go test -count=1 -v -cover . -p 1 -timeout=20m -race
cd $PWD
