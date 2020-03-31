/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	sidetreeobserver "github.com/trustbloc/sidetree-core-go/pkg/observer"
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

// Start starts observer routines
func Start(blockchainClient batch.BlockchainClient, cas batch.CASClient, operationStoreProvider sidetreeobserver.OperationStoreProvider) {
	providers := &sidetreeobserver.Providers{
		Ledger:           &ledger{blockChainClient: blockchainClient},
		DCASClient:       dcas{cas: cas},
		OpStoreProvider:  operationStoreProvider,
		OpFilterProvider: &sidetreeobserver.NoopOperationFilterProvider{},
	}

	sidetreeobserver.New(providers).Start()
}
