/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
)

// MockProtocolClient mocks protocol for testing purposes.
type MockProtocolClient struct {
	Protocol protocol.Protocol
}

// NewMockProtocolClient creates mocks protocol client
func NewMockProtocolClient() *MockProtocolClient {

	return &MockProtocolClient{
		Protocol: protocol.Protocol{
			StartingBlockChainTime:       0,
			HashAlgorithmInMultiHashCode: 18,
			MaxOperationsPerBatch:        1, // one operation per batch - batch gets cut right away
			MaxDeltaByteSize:             200000,
		},
	}
}

// Current mocks getting last protocol version
func (m *MockProtocolClient) Current() protocol.Protocol {
	return m.Protocol
}

// NewMockProtocolClientProvider creates new mock protocol client provider
func NewMockProtocolClientProvider() *MockProtocolClientProvider {
	return &MockProtocolClientProvider{
		ProtocolClient: NewMockProtocolClient(),
	}
}

// MockProtocolClientProvider implements mock protocol client provider
type MockProtocolClientProvider struct {
	ProtocolClient protocol.Client
}

// ForNamespace provides protocol client for namespace
func (m *MockProtocolClientProvider) ForNamespace(namespace string) (protocol.Client, error) {
	return m.ProtocolClient, nil
}
