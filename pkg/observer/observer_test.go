/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/observer"
	"github.com/trustbloc/sidetree-mock/pkg/mocks"
)

func TestStartObserver(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		var rw sync.RWMutex
		txNum := make(map[uint64]*struct{}, 0)
		hits := 0

		opStore := &mockOperationStoreClient{putFunc: func(ops []*batch.Operation) error {
			rw.Lock()
			defer rw.Unlock()

			for _, op := range ops {
				txNum[op.TransactionNumber] = nil
				hits++
			}

			return nil
		}}

		Start(&mockBlockchainClient{readValue: []*observer.SidetreeTxn{{AnchorAddress: "anchorAddress", TransactionNumber: 0},
			{AnchorAddress: "anchorAddress", TransactionNumber: 1}}}, mockCASClient{readFunc: func(key string) ([]byte, error) {
			if key == "anchorAddress" {
				return json.Marshal(&observer.AnchorFile{})
			}
			b, err := json.Marshal(batch.Operation{ID: "did:sidetree:1234"})
			require.NoError(t, err)
			return json.Marshal(&observer.BatchFile{Operations: []string{docutil.EncodeToString(b)}})
		}}, mocks.NewMockOpStoreProvider(opStore))
		time.Sleep(2000 * time.Millisecond)
		rw.RLock()
		require.Equal(t, 2, hits)
		require.Equal(t, 2, len(txNum))
		_, ok := txNum[0]
		require.True(t, ok)
		_, ok = txNum[1]
		require.True(t, ok)
		rw.RUnlock()

	})
}

type mockBlockchainClient struct {
	readValue []*observer.SidetreeTxn
}

// Read ledger transaction
func (m mockBlockchainClient) WriteAnchor(anchor string) error {
	return nil

}
func (m mockBlockchainClient) Read(sinceTransactionNumber int) (bool, *observer.SidetreeTxn) {
	if sinceTransactionNumber+1 >= len(m.readValue) {
		return false, nil
	}
	return false, m.readValue[sinceTransactionNumber+1]
}

type mockCASClient struct {
	readFunc func(key string) ([]byte, error)
}

func (m mockCASClient) Write(content []byte) (string, error) {
	return "", nil
}

func (m mockCASClient) Read(key string) ([]byte, error) {
	if m.readFunc != nil {
		return m.readFunc(key)
	}
	return nil, nil
}

type mockOperationStoreClient struct {
	putFunc func(ops []*batch.Operation) error
}

func (m mockOperationStoreClient) Put(ops []*batch.Operation) error {
	if m.putFunc != nil {
		return m.putFunc(ops)
	}
	return nil
}
