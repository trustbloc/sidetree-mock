/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"fmt"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
)

const maxBatchFileSize = 2000000 // in bytes

// MockProtocolClient mocks protocol for testing purposes.
type MockProtocolClient struct {
	protocols []protocol.Protocol
}

// NewMockProtocolClient creates mocks protocol client
func NewMockProtocolClient() *MockProtocolClient {
	latest := protocol.Protocol{
		GenesisTime:                  0,
		HashAlgorithmInMultiHashCode: 18,
		MaxOperationCount:            1, // one operation per batch - batch gets cut right away
		MaxOperationSize:             200000,
		CompressionAlgorithm:         "GZIP",
		MaxChunkFileSize:             maxBatchFileSize,
		MaxMapFileSize:               maxBatchFileSize,
		MaxAnchorFileSize:            maxBatchFileSize,
		EnableReplacePatch:           true,
		SignatureAlgorithms:          []string{"EdDSA", "ES256", "ES256K"},
		KeyAlgorithms:                []string{"Ed25519", "P-256", "secp256k1"},
	}

	// has to be sorted for mock client to work
	versions := []protocol.Protocol{latest}

	return &MockProtocolClient{protocols: versions}
}

// Current mocks getting last protocol version
func (m *MockProtocolClient) Current() protocol.Protocol {
	return m.protocols[len(m.protocols)-1]
}

// Get mocks getting protocol version based on blockchain(transaction) time
func (m *MockProtocolClient) Get(transactionTime uint64) (protocol.Protocol, error) {
	for i := len(m.protocols) - 1; i >= 0; i-- {
		if transactionTime >= m.protocols[i].GenesisTime {
			return m.protocols[i], nil
		}
	}

	return protocol.Protocol{}, fmt.Errorf("protocol parameters are not defined for block chain time: %d", transactionTime)
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
