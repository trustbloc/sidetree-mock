/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/compression"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/txnprovider/models"

	"github.com/trustbloc/sidetree-mock/pkg/mocks"
)

func TestStartObserver(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		var rw sync.RWMutex
		txNum := make(map[uint64]*struct{}, 0)
		hits := 0

		opStore := &mockOperationStoreClient{
			putFunc: func(ops []*batch.AnchoredOperation) error {
				rw.Lock()
				defer rw.Unlock()

				for _, op := range ops {
					txNum[op.TransactionNumber] = nil
					hits++
				}

				return nil
			},
		}

		bcc := &mockBlockchainClient{
			readValue: []*txn.SidetreeTxn{
				{Namespace: mocks.DefaultNS, AnchorString: "1.anchorAddress", TransactionNumber: 0},
				{Namespace: mocks.DefaultNS, AnchorString: "1.anchorAddress", TransactionNumber: 1}},
		}

		casClient := mockCASClient{readFunc: func(key string) ([]byte, error) {
			if key == "anchorAddress" {
				return compress(&models.AnchorFile{MapFileHash: "mapAddress",
					Operations: models.Operations{
						Create: []models.CreateOperation{{
							SuffixData: getSuffixData(),
						}}}})
			}
			if key == "mapAddress" {
				return compress(&models.MapFile{Chunks: []models.Chunk{{ChunkFileURI: "chunkAddress"}}})
			}
			if key == "chunkAddress" {
				return compress(&models.ChunkFile{Deltas: []*model.DeltaModel{getDelta()}})
			}
			return nil, nil
		}}

		Start(bcc, mocks.NewMockProtocolClientProvider().WithOpStore(opStore).WithCasClient(casClient))

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
func (m mockBlockchainClient) WriteAnchor(anchor string, protocolGenesisTime uint64) error {
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
	putFunc func(ops []*batch.AnchoredOperation) error
}

func (m mockOperationStoreClient) Put(ops []*batch.AnchoredOperation) error {
	if m.putFunc != nil {
		return m.putFunc(ops)
	}
	return nil
}

func getSuffixData() *model.SuffixDataModel {
	return &model.SuffixDataModel{
		DeltaHash: getEncodedMultihash([]byte(validDoc)),

		RecoveryCommitment: getEncodedMultihash([]byte("commitment")),
	}
}

func getEncodedMultihash(data []byte) string {
	const sha2_256 = 18
	mh, err := docutil.ComputeMultihash(sha2_256, data)
	if err != nil {
		panic(err)
	}
	return docutil.EncodeToString(mh)
}

func getDelta() *model.DeltaModel {
	patches, err := patch.PatchesFromDocument(validDoc)
	if err != nil {
		panic(err)
	}

	return &model.DeltaModel{
		Patches:          patches,
		UpdateCommitment: getEncodedMultihash([]byte("")),
	}
}

func compress(model interface{}) ([]byte, error) {
	bytes, err := docutil.MarshalCanonical(model)
	if err != nil {
		return nil, err
	}

	cp := compression.New(compression.WithDefaultAlgorithms())

	return cp.Compress("GZIP", bytes)
}

const validDoc = `{"key": "value"}`
