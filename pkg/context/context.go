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
		ProtocolClient: pc,
		AnchorWriter:   mocks.NewMockAnchorWriter(nil),
		OpQueue:        &opqueue.MemQueue{},
	}
}

// ServerContext implements batch context
type ServerContext struct {
	ProtocolClient protocol.Client
	AnchorWriter   *mocks.MockAnchorWriter
	OpQueue        *opqueue.MemQueue
}

// Protocol returns the ProtocolClient
func (m *ServerContext) Protocol() protocol.Client {
	return m.ProtocolClient
}

// Anchor returns anchor writer
func (m *ServerContext) Anchor() batch.AnchorWriter {
	return m.AnchorWriter
}

// OperationQueue returns the queue containing the pending operations
func (m *ServerContext) OperationQueue() cutter.OperationQueue {
	return m.OpQueue
}
