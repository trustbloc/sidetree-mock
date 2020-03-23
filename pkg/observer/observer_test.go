/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	batchapi "github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/observer"
)

func TestStartObserver(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		txNum := make(map[uint64]*struct{}, 0)
		hits := 0
		var rw sync.RWMutex
		Start(&mockBlockchainClient{readValue: []*observer.SidetreeTxn{{AnchorAddress: "anchorAddress", TransactionNumber: 0},
			{AnchorAddress: "anchorAddress", TransactionNumber: 1}}}, mockCASClient{readFunc: func(key string) ([]byte, error) {
			if key == "anchorAddress" {
				return json.Marshal(&observer.AnchorFile{})
			}
			b, err := json.Marshal(batch.Operation{ID: "did:sidetree:1234"})
			require.NoError(t, err)
			return json.Marshal(&observer.BatchFile{Operations: []string{docutil.EncodeToString(b)}})
		}}, mockOperationStoreClient{putFunc: func(ops *batch.Operation) error {
			rw.Lock()
			txNum[ops.TransactionNumber] = nil
			hits++
			rw.Unlock()
			return nil
		}})
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

	t.Run("test error from operationStore put", func(t *testing.T) {
		err := operationStore{operationStoreClient: mockOperationStoreClient{putFunc: func(ops *batch.Operation) error {
			return fmt.Errorf("put error")
		}}}.Put([]*batchapi.Operation{&batch.Operation{ID: "did:sidetree:1234", Type: "1"}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "put in operation store failed")
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
	putFunc func(ops *batch.Operation) error
}

func (m mockOperationStoreClient) Get(uniqueSuffix string) ([]*batch.Operation, error) {
	return nil, nil
}

func (m mockOperationStoreClient) Put(op *batch.Operation) error {
	if m.putFunc != nil {
		return m.putFunc(op)
	}
	return nil
}
