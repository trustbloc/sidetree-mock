/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	batchapi "github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	sidetreeobserver "github.com/trustbloc/sidetree-core-go/pkg/observer"
	"github.com/trustbloc/sidetree-core-go/pkg/processor"
)

var logger = logrus.New()

type ledger struct {
	blockChainClient batch.BlockchainClient
}

func (l *ledger) RegisterForSidetreeTxn() <-chan []sidetreeobserver.SidetreeTxn {
	// TODO make it configurable
	ticker := time.NewTicker(500 * time.Millisecond)
	anchorFileAddressChan := make(chan []sidetreeobserver.SidetreeTxn, 100)
	sinceTransactionNumber := -1
	go func() {
		for range ticker.C {
			moreTransactions := true
			sidetreeTxns := make([]sidetreeobserver.SidetreeTxn, 0)
			for moreTransactions {
				var sidetreeTxn *sidetreeobserver.SidetreeTxn
				moreTransactions, sidetreeTxn = l.blockChainClient.Read(sinceTransactionNumber)
				if sidetreeTxn != nil {
					sinceTransactionNumber = int(sidetreeTxn.TransactionNumber)
					logger.Debugf("found sidetree txn %d in ledger", sidetreeTxn.TransactionNumber)
					sidetreeTxns = append(sidetreeTxns, *sidetreeTxn)
				}
			}
			if len(sidetreeTxns) > 0 {
				anchorFileAddressChan <- sidetreeTxns
			}
		}
	}()
	return anchorFileAddressChan
}

type dcas struct {
	cas batch.CASClient
}

func (d dcas) Read(key string) ([]byte, error) {
	return d.cas.Read(key)
}

type operationStore struct {
	operationStoreClient processor.OperationStoreClient
}

func (o operationStore) Put(ops []*batchapi.Operation) error {
	for _, op := range ops {
		if err := o.operationStoreClient.Put(op); err != nil {
			return errors.Wrap(err, "put in operation store failed")
		}
	}
	return nil
}

// Start starts observer routines
func Start(blockchainClient batch.BlockchainClient, cas batch.CASClient, operationStoreClient processor.OperationStoreClient) {
	providers := &sidetreeobserver.Providers{
		Ledger:           &ledger{blockChainClient: blockchainClient},
		DCASClient:       dcas{cas: cas},
		OpStore:          operationStore{operationStoreClient: operationStoreClient},
		OpFilterProvider: &sidetreeobserver.NoopOperationFilterProvider{},
	}

	sidetreeobserver.Start(providers)
}
