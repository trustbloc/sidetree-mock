/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"

	log "github.com/sirupsen/logrus"
)

// MockCasClient mocks CAS for running server in test mode. It has extra functionality to detect
// writing of the batch file to CAS. In this case it adds operations directly into operation store.
// This is a shortcut for running server in test mode (in the absence of observer component)
type MockCasClient struct {
	CAS *mocks.MockCasClient
}

// NewMockCasClient creates mock cas client;
func NewMockCasClient(err error) *MockCasClient {
	return &MockCasClient{CAS: mocks.NewMockCasClient(nil)}
}

// Write writes the given content to CAS.
// returns the SHA256 hash in base64url encoding which represents the address of the content.
func (m *MockCasClient) Write(content []byte) (string, error) {

	address, err := m.CAS.Write(content)
	if err != nil {
		return "", err
	}

	log.Debugf("added content with address[%s]", address)

	return address, nil
}

// Read reads the content of the given address in CAS.
// returns the content of the given address.
func (m *MockCasClient) Read(address string) ([]byte, error) {
	return m.CAS.Read(address)
}
