/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/cutter"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/opqueue"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/processor"

	servermocks "github.com/trustbloc/sidetree-mock/pkg/mocks"
)

func New(opStoreClient processor.OperationStoreClient) (*ServerContext, error) { // nolint

	cas := servermocks.NewMockCasClient(nil)

	ctx := &ServerContext{
		ProtocolClient:       servermocks.NewMockProtocolClient(),
		CasClient:            cas,
		BlockchainClient:     mocks.NewMockBlockchainClient(nil),
		OperationStoreClient: opStoreClient,
		OpQueue:              &opqueue.MemQueue{},
	}

	return ctx, nil

}

// ServerContext implements batch context
type ServerContext struct {
	ProtocolClient       *servermocks.MockProtocolClient
	CasClient            *servermocks.MockCasClient
	BlockchainClient     *mocks.MockBlockchainClient
	OperationStoreClient processor.OperationStoreClient
	OpQueue              *opqueue.MemQueue
}

// Protocol returns the ProtocolClient
func (m *ServerContext) Protocol() protocol.Client {
	return m.ProtocolClient
}

// Blockchain returns the block chain client
func (m *ServerContext) Blockchain() batch.BlockchainClient {
	return m.BlockchainClient
}

// CAS returns the CAS client
func (m *ServerContext) CAS() cas.Client {
	return m.CasClient
}

// OperationStore returns the OperationStore client
func (m *ServerContext) OperationStore() processor.OperationStoreClient {
	return m.OperationStoreClient
}

// OperationQueue returns the queue containing the pending operations
func (m *ServerContext) OperationQueue() cutter.OperationQueue {
	return m.OpQueue
}
