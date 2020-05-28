/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/txnhandler"

	sidetreeobserver "github.com/trustbloc/sidetree-core-go/pkg/observer"
)

var logger = logrus.New()

type ledger struct {
	blockChainClient batch.BlockchainClient
}

func (l *ledger) RegisterForSidetreeTxn() <-chan []txn.SidetreeTxn {
	// TODO make it configurable
	ticker := time.NewTicker(500 * time.Millisecond)
	anchorFileAddressChan := make(chan []txn.SidetreeTxn, 100)
	sinceTransactionNumber := -1
	go func() {
		for range ticker.C {
			moreTransactions := true
			sidetreeTxns := make([]txn.SidetreeTxn, 0)
			for moreTransactions {
				var sidetreeTxn *txn.SidetreeTxn
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

// Start starts observer routines
func Start(blockchainClient batch.BlockchainClient, cas cas.Client, operationStoreProvider sidetreeobserver.OperationStoreProvider, p protocol.Client) {
	providers := &sidetreeobserver.Providers{
		Ledger:           &ledger{blockChainClient: blockchainClient},
		TxnOpsProvider:   txnhandler.New(cas, p),
		OpStoreProvider:  operationStoreProvider,
		OpFilterProvider: &sidetreeobserver.NoopOperationFilterProvider{},
	}

	sidetreeobserver.New(providers).Start()
}
