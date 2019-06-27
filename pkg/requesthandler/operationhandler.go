/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package requesthandler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-node/models"
)

//OperationHandler creates an operation from request and delegates document processing to document handler
type OperationHandler struct {
	namespace  string
	protocol   protocol.Client
	docHandler DocumentHandler
}

// DocumentHandler is an interface which allows for handling document operations (create, update, delete, revoke)
type DocumentHandler interface {
	ProcessOperation(operation batch.Operation) (document.Document, error)
}

// NewOperationHandler creates a new operation handler
func NewOperationHandler(namespace string, protocol protocol.Client, handler DocumentHandler) *OperationHandler {
	return &OperationHandler{
		namespace:  namespace,
		protocol:   protocol,
		docHandler: handler,
	}
}

//HandleOperationRequest returns responder for create, update, delete, revoke operations
func (r *OperationHandler) HandleOperationRequest(request *models.Request) middleware.Responder {

	operation, err := r.getOperation(request)
	if err != nil {
		return &BadRequestError{&models.Error{Message: swag.String(err.Error())}}
	}

	//handling operation based on validated operation type and encoded payload from request bytes
	didDoc, err := r.docHandler.ProcessOperation(operation)
	if err != nil {
		return &InternalServerError{&models.Error{Message: swag.String(err.Error())}}
	}

	return &Response{Body: &models.Response{Body: didDoc}, Status: http.StatusOK}

}

func (r *OperationHandler) getOperation(request *models.Request) (batch.Operation, error) {
	operation := batch.Operation{
		EncodedPayload:               swag.StringValue(request.Payload),
		Signature:                    swag.StringValue(request.Signature),
		SigningKeyID:                 swag.StringValue(request.Header.Kid),
		Type:                         getOperationType(request.Header.Operation),
		HashAlgorithmInMultiHashCode: r.protocol.Current().HashAlgorithmInMultiHashCode,
	}

	switch operation.Type {
	case batch.OperationTypeCreate:

		uniqueSuffix, err := docutil.GetOperationHash(operation)
		if err != nil {
			return batch.Operation{}, err
		}
		operation.UniqueSuffix = uniqueSuffix
		operation.ID = r.namespace + uniqueSuffix

		operation.OperationNumber = 0

	case batch.OperationTypeUpdate:
		decodedPayload, err := getDecodedPayload(swag.StringValue(request.Payload))
		if err != nil {
			return batch.Operation{}, errors.New("request payload doesn't follow the expected update payload schema")
		}
		operation.OperationNumber = decodedPayload.OperationNumber
		operation.UniqueSuffix = decodedPayload.DidUniqueSuffix
		operation.PreviousOperationHash = decodedPayload.PreviousOperationHash
		operation.Patch = decodedPayload.Patch
		operation.ID = r.namespace + decodedPayload.DidUniqueSuffix

	default:
		return batch.Operation{}, errors.New("operation type not implemented")
	}
	return operation, nil
}

func getDecodedPayload(encodedPayload string) (*payloadSchema, error) {
	decodedPayload, err := docutil.DecodeString(encodedPayload)
	if err != nil {
		return nil, err
	}
	uploadPayloadSchema := &payloadSchema{}
	err = json.Unmarshal(decodedPayload, uploadPayloadSchema)
	if err != nil {
		return nil, err
	}
	return uploadPayloadSchema, nil
}

func getOperationType(t models.OperationType) batch.OperationType {

	switch t {
	case models.OperationTypeCreate:
		return batch.OperationTypeCreate
	case models.OperationTypeUpdate:
		return batch.OperationTypeUpdate
	case models.OperationTypeDelete:
		return batch.OperationTypeDelete
	case models.OperationTypeRecover:
		return batch.OperationTypeRecover
	}

	return ""
}

//payloadSchema is the struct for update payload
type payloadSchema struct {
	//The unique suffix of the DID
	DidUniqueSuffix string
	//The number incremented from the last change version number. 1 if first change.
	OperationNumber uint
	//The hash of the previous operation made to the DID Document.
	PreviousOperationHash string
	//An RFC 6902 JSON patch to the current DID Document
	Patch jsonpatch.Patch
}
