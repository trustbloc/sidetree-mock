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
		isCalled := false
		var rw sync.RWMutex
		Start(mockBlockchainClient{readValue: &observer.SidetreeTxn{AnchorAddress: "anchorAddress"}}, mockCASClient{readFunc: func(key string) ([]byte, error) {
			if key == "anchorAddress" {
				return json.Marshal(&observer.AnchorFile{})
			}
			b, err := json.Marshal(batch.Operation{})
			require.NoError(t, err)
			return json.Marshal(&observer.BatchFile{Operations: []string{docutil.EncodeToString(b)}})
		}}, mockOperationStoreClient{putFunc: func(ops batch.Operation) error {
			rw.Lock()
			isCalled = true
			rw.Unlock()
			return nil
		}})
		time.Sleep(1000 * time.Millisecond)
		rw.RLock()
		require.True(t, isCalled)
		rw.RUnlock()
	})

	t.Run("test error from operationStore put", func(t *testing.T) {
		err := operationStore{operationStoreClient: mockOperationStoreClient{putFunc: func(ops batch.Operation) error {
			return fmt.Errorf("put error")
		}}}.Put([]batchapi.Operation{{Type: "1"}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "put in operation store failed")
	})
}

type mockBlockchainClient struct {
	readValue *observer.SidetreeTxn
}

// Read ledger transaction
func (m mockBlockchainClient) WriteAnchor(anchor string) error {
	return nil

}
func (m mockBlockchainClient) Read(sinceTransactionNumber int) (bool, *observer.SidetreeTxn) {
	return false, m.readValue
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
	putFunc func(ops batch.Operation) error
}

func (m mockOperationStoreClient) Get(uniqueSuffix string) ([]batch.Operation, error) {
	return nil, nil
}

func (m mockOperationStoreClient) Put(op batch.Operation) error {
	if m.putFunc != nil {
		return m.putFunc(op)
	}
	return nil
}
