/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"errors"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

const (
	sha2_256  = 18
	namespace = "did:sidetree:"
)

// NewMockDocumentHandler creates mock document handler
func NewMockDocumentHandler(err error) *MockDocumentHandler {
	return &MockDocumentHandler{
		Namespace: namespace,
		Protocol: protocol.Protocol{
			HashAlgorithmInMultiHashCode: sha2_256,
		},
		Store: make(map[string]document.Document),
		Err:   err,
	}
}

// MockDocumentHandler mocks document handler
type MockDocumentHandler struct {
	Err       error
	Namespace string
	Protocol  protocol.Protocol
	Store     map[string]document.Document
}

// ProcessOperation mocks process operation
func (m *MockDocumentHandler) ProcessOperation(operation batch.Operation) (document.Document, error) {

	if m.Err != nil {
		return nil, m.Err
	}

	if operation.Type != batch.OperationTypeCreate {
		return nil, nil
	}

	// create operation returns document
	id, err := docutil.CalculateID(m.Namespace, operation.EncodedPayload, m.Protocol.HashAlgorithmInMultiHashCode)
	if err != nil {
		return nil, err
	}

	doc, err := getDocumentFromPayload(operation)
	if err != nil {
		return nil, err
	}

	doc = applyID(doc, id)

	m.Store[id] = doc

	return doc, nil

}

func getDocumentFromPayload(operation batch.Operation) (document.Document, error) {

	decodedBytes, err := docutil.DecodeString(operation.EncodedPayload)
	if err != nil {
		return nil, err
	}

	return document.FromBytes(decodedBytes)
}

//ResolveDocument mocks resolve document
func (m *MockDocumentHandler) ResolveDocument(idOrDocument string) (document.Document, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	if _, ok := m.Store[idOrDocument]; !ok {
		return nil, errors.New("not found")
	}

	return m.Store[idOrDocument], nil
}

// helper function to insert ID into document
func applyID(doc document.Document, id string) document.Document {

	// apply id to document
	doc["id"] = id
	return doc
}
