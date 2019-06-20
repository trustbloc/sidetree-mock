// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/sidetree-node/test/bddtests

go 1.12

require (
	github.com/DATA-DOG/godog v0.7.13
	github.com/fsouza/go-dockerclient v1.3.0
	github.com/go-openapi/swag v0.19.0
	github.com/pkg/errors v0.8.1
	github.com/sirupsen/logrus v1.3.0
	github.com/stretchr/testify v1.3.0
	github.com/trustbloc/sidetree-core-go v0.0.0-20190531160340-1ce667055015
	github.com/trustbloc/sidetree-node v0.0.0

)

replace github.com/trustbloc/sidetree-node => ../..
