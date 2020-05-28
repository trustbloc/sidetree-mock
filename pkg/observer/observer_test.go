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
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
	"github.com/trustbloc/sidetree-core-go/pkg/txnhandler/models"
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

		Start(&mockBlockchainClient{readValue: []*txn.SidetreeTxn{{AnchorAddress: "anchorAddress", TransactionNumber: 0},
			{AnchorAddress: "anchorAddress", TransactionNumber: 1}}}, mockCASClient{readFunc: func(key string) ([]byte, error) {
			if key == "anchorAddress" {
				return json.Marshal(&models.AnchorFile{MapFileHash: "mapAddress",
					Operations: models.Operations{
						Create: []models.CreateOperation{{
							SuffixData: getSuffixData(),
							Namespace:  "did:sidetree",
						}}}})
			}
			if key == "mapAddress" {
				return json.Marshal(&models.MapFile{Chunks: []models.Chunk{{ChunkFileURI: "chunkAddress"}}})
			}
			if key == "chunkAddress" {
				return json.Marshal(&models.ChunkFile{Deltas: []string{getDelta()}})
			}
			return nil, nil
		}}, mocks.NewMockOpStoreProvider(opStore), mocks.NewMockProtocolClient())
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
	readValue []*txn.SidetreeTxn
}

// Read ledger transaction
func (m mockBlockchainClient) WriteAnchor(anchor string) error {
	return nil

}
func (m mockBlockchainClient) Read(sinceTransactionNumber int) (bool, *txn.SidetreeTxn) {
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

func getSuffixData() string {
	model := &model.SuffixDataModel{
		DeltaHash: getEncodedMultihash([]byte(validDoc)),
		RecoveryKey: &jws.JWK{
			Kty: "kty",
			Crv: "crv",
			X:   "x",
		},
		RecoveryCommitment: getEncodedMultihash([]byte("commitment")),
	}

	bytes, err := json.Marshal(model)
	if err != nil {
		panic(err)
	}

	return docutil.EncodeToString(bytes)
}

func getEncodedMultihash(data []byte) string {
	const sha2_256 = 18
	mh, err := docutil.ComputeMultihash(sha2_256, data)
	if err != nil {
		panic(err)
	}
	return docutil.EncodeToString(mh)
}

func getDelta() string {
	patches, err := patch.PatchesFromDocument(validDoc)
	if err != nil {
		panic(err)
	}

	model := &model.DeltaModel{
		Patches:          patches,
		UpdateCommitment: getEncodedMultihash([]byte("")),
	}

	bytes, err := json.Marshal(model)
	if err != nil {
		panic(err)
	}

	return docutil.EncodeToString(bytes)
}

const validDoc = `{"key": "value"}`
