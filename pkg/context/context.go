/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/cutter"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/opqueue"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

// New returns a new server context
func New(pc protocol.Client) *ServerContext {
	return &ServerContext{
		ProtocolClient:   pc,
		BlockchainClient: mocks.NewMockBlockchainClient(nil),
		OpQueue:          &opqueue.MemQueue{},
	}
}

// ServerContext implements batch context
type ServerContext struct {
	ProtocolClient   protocol.Client
	BlockchainClient *mocks.MockBlockchainClient
	OpQueue          *opqueue.MemQueue
}

// Protocol returns the ProtocolClient
func (m *ServerContext) Protocol() protocol.Client {
	return m.ProtocolClient
}

// Blockchain returns the block chain client
func (m *ServerContext) Blockchain() batch.BlockchainClient {
	return m.BlockchainClient
}

// OperationQueue returns the queue containing the pending operations
func (m *ServerContext) OperationQueue() cutter.OperationQueue {
	return m.OpQueue
}
