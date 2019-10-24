// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/sidetree-mock/test/bddtests

go 1.12

require (
	github.com/DATA-DOG/godog v0.7.13
	github.com/fsouza/go-dockerclient v1.3.0
	github.com/go-openapi/swag v0.19.0
	github.com/pkg/errors v0.8.1
	github.com/sirupsen/logrus v1.3.0
	github.com/stretchr/testify v1.3.0
	github.com/trustbloc/sidetree-core-go v0.0.0-20191017153620-a489e16494b3
	github.com/trustbloc/sidetree-mock v0.0.0

)

replace github.com/trustbloc/sidetree-mock => ../..
