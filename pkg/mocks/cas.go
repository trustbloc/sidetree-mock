/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"encoding/json"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/batch/filehandler"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"

	log "github.com/sirupsen/logrus"
)

// MockCasClient mocks CAS for running server in test mode. It has extra functionality to detect
// writing of the batch file to CAS. In this case it adds operations directly into operation store.
// This is a shortcut for running server in test mode (in the absence of observer component)
type MockCasClient struct {
	CAS      *mocks.MockCasClient
	OpsStore *mocks.MockOperationStore // add as shortcut for running server in test mode
}

// NewMockCasClient creates mock cas client;
func NewMockCasClient(err error) *MockCasClient {
	return &MockCasClient{CAS: mocks.NewMockCasClient(nil)}
}

// Write writes the given content to CAS.
// returns the SHA256 hash in base64url encoding which represents the address of the content.
func (m *MockCasClient) Write(content []byte) (string, error) {

	address, err := m.CAS.Write(content)
	if err != nil {
		return "", err
	}

	log.Debugf("added content with address[%s]", address)

	if m.OpsStore != nil {
		// Server is running in 'test' mode
		var bf filehandler.BatchFile
		err = json.Unmarshal(content, &bf)
		if err == nil {
			// cas is storing batch file; store operations into operations processor
			m.storeOperationsFromBatchFile(bf)
		}
	}

	return address, nil
}

func (m *MockCasClient) storeOperationsFromBatchFile(batchFile filehandler.BatchFile) {
	for _, encodedOp := range batchFile.Operations {
		err := m.storeOperation(encodedOp)
		if err != nil {
			panic(err)
		}
	}
}
func (m *MockCasClient) storeOperation(encodedOp string) error {

	opBytes, err := docutil.DecodeString(encodedOp)
	if err != nil {
		return err
	}

	op := batch.Operation{}
	err = json.Unmarshal(opBytes, &op)
	if err != nil {
		log.Errorf("unmarshal operation failed: %s", err.Error())
		return err
	}

	log.Debugf("adding operation for uniqueSuffix[%s] to the mock store", op.UniqueSuffix)
	if err := m.OpsStore.Put(op); err != nil {
		return err
	}

	return nil
}

// Read reads the content of the given address in CAS.
// returns the content of the given address.
func (m *MockCasClient) Read(address string) ([]byte, error) {
	return m.CAS.Read(address)
}
