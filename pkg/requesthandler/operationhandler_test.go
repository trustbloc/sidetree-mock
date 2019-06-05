/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package requesthandler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/trustbloc/sidetree-core-go/pkg/api/batch"

	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-node/pkg/requesthandler/mocks"

	coremocks "github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-node/models"
	"github.com/trustbloc/sidetree-node/restapi/operations"
)

const (
	sideTreeCreateRequestPath string = "testdata/sideTreeCreateRequest.json"
	sideTreeUpdateRequestPath string = "testdata/sideTreeUpdateRequest.json"
	namespace                 string = "did:sidetree:"
)

func TestHandleCreateOperation(t *testing.T) {
	operationHandler := operationHandler()
	require.NotNil(t, operationHandler)

	request := newCreateRequest()

	response := httptest.NewRecorder()
	operationHandler.HandleOperationRequest(request).WriteResponse(response, runtime.JSONProducer())
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), expectedDID())
	require.Contains(t, response.Body.String(), "https://w3id.org/did/v1")
}

func TestHandleCreateOperation_DocumentHandlerError(t *testing.T) {

	operationHandler := operationHandler()
	require.NotNil(t, operationHandler)

	testErr := fmt.Errorf("test error")
	operationHandler.docHandler = mocks.NewMockDocumentHandler(testErr)

	request := newCreateRequest()

	response := httptest.NewRecorder()
	operationHandler.HandleOperationRequest(request).WriteResponse(response, runtime.JSONProducer())
	require.Equal(t, http.StatusInternalServerError, response.Code)
}

func TestHandleCreateOperation_ProtocolError(t *testing.T) {

	operationHandler := operationHandler()
	require.NotNil(t, operationHandler)

	p := coremocks.NewMockProtocolClient()
	p.Protocol = protocol.Protocol{
		HashAlgorithmInMultiHashCode: 999, // Invalid mulithash
	}

	operationHandler.protocol = p

	request := newCreateRequest()
	response := httptest.NewRecorder()
	operationHandler.HandleOperationRequest(request).WriteResponse(response, runtime.JSONProducer())
	require.Equal(t, http.StatusBadRequest, response.Code)
}

func TestHandlerUpdateOperation(t *testing.T) {
	operationHandler := operationHandler()
	require.NotNil(t, operationHandler)

	request := newUpdateRequest()

	response := httptest.NewRecorder()
	operationHandler.HandleOperationRequest(request.Request).WriteResponse(response, runtime.JSONProducer())
	require.Equal(t, http.StatusOK, response.Code)
}

func TestGetOperationType(t *testing.T) {

	opType := getOperationType(models.OperationTypeCreate)
	require.Equal(t, batch.OperationTypeCreate, opType)

	opType = getOperationType(models.OperationTypeUpdate)
	require.Equal(t, batch.OperationTypeUpdate, opType)

	opType = getOperationType(models.OperationTypeDelete)
	require.Equal(t, batch.OperationTypeDelete, opType)

	opType = getOperationType(models.OperationTypeRecover)
	require.Equal(t, batch.OperationTypeRecover, opType)

	opType = getOperationType("type")
	require.Equal(t, batch.OperationType(""), opType)

}

func TestGetDecodedPayload(t *testing.T) {

	// scenario: illegal payload (not base64)
	doc, err := getDecodedPayload("{}")
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "illegal base64 data")

	// scenario: illegal payload (invalid json)
	doc, err = getDecodedPayload(docutil.EncodeToString([]byte("[test : 123]")))
	require.NotNil(t, err)
	require.Nil(t, doc)
	require.Contains(t, err.Error(), "invalid character")
}

func newUpdateRequest() operations.PostDocumentParams {
	req := &models.Request{}
	fileBytes := reader(sideTreeUpdateRequestPath)
	err := json.NewDecoder(fileBytes).Decode(req)
	if err != nil {
		panic(fmt.Sprintf("failed to decode test request: %s", err))
	}
	return operations.PostDocumentParams{
		HTTPRequest: httptest.NewRequest(http.MethodPost, "/.sidetree", bytes.NewBuffer(marshal(req))),
		Request:     req,
	}
}

func expectedDID() string {
	encodedPayload := getEncodedPayload()
	did, err := docutil.CalculateID(namespace, encodedPayload, getProtocol().HashAlgorithmInMultiHashCode)
	if err != nil {
		panic(err)
	}
	return did
}

func reader(filename string) io.Reader {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	return f
}

// sideTreeRequestFromReader creates an instance of Operation by reading a JSON document from Reader
func sideTreeRequestFromReader(r io.Reader) (*models.Request, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return &models.Request{}, err
	}

	req := models.Request{}
	err = json.Unmarshal(data, &req)
	if err != nil {
		return &models.Request{}, err
	}

	return &req, nil
}

func getEncodedPayload() string {
	f, err := os.Open(sideTreeCreateRequestPath)
	if err != nil {
		panic(err)
	}
	request, err := sideTreeRequestFromReader(f)
	if err != nil {
		panic(err)
	}
	return swag.StringValue(request.Payload)
}

func getProtocol() protocol.Protocol {
	return coremocks.NewMockProtocolClient().Current()
}

func marshal(request *models.Request) []byte {
	b, err := json.Marshal(request)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal request to json bytes: %s", err))
	}
	return b
}

func newCreateRequest() *models.Request {
	req := &models.Request{}
	fileBytes := reader(sideTreeCreateRequestPath)
	err := json.NewDecoder(fileBytes).Decode(req)
	if err != nil {
		panic(err)
	}
	return req
}

func operationHandler() *OperationHandler {
	return NewOperationHandler(namespace, coremocks.NewMockProtocolClient(), mocks.NewMockDocumentHandler(nil))
}
