/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package requesthandler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-node/pkg/requesthandler/mocks"

	coremocks "github.com/trustbloc/sidetree-core-go/pkg/mocks"
)

const did = "did:sidetree:EiDOQXC2GnoVyHwIRbjhLx_cNc6vmZaS04SZjZdlLLAPRg=="

func TestResolutionHandler_HandleResolveRequest(t *testing.T) {

	response := httptest.NewRecorder()

	protocol := coremocks.NewMockProtocolClient()
	docHandler := mocks.NewMockDocumentHandler(nil)
	operationHandler := NewOperationHandler(namespace, protocol, docHandler)
	resolutionHandler := NewResolutionHandler(namespace, protocol, docHandler)

	// insert create operation
	request := newCreateRequest()
	operationHandler.HandleOperationRequest(request).WriteResponse(response, runtime.JSONProducer())

	// resolve document
	response = httptest.NewRecorder()
	resolutionHandler.HandleResolveRequest(did).WriteResponse(response, runtime.JSONProducer())
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), expectedDID())
	require.Contains(t, response.Body.String(), "https://w3id.org/did/v1")
}

func TestResolutionHandler_HandleResolveRequest_NotFound(t *testing.T) {

	resolutionHandler := resolutionHandler()
	response := httptest.NewRecorder()

	// not found scenario
	resolutionHandler.HandleResolveRequest(did).WriteResponse(response, runtime.JSONProducer())
	require.Equal(t, http.StatusNotFound, response.Code)
}

func TestResolutionHandler_HandleResolveRequest_MethodNotSupported(t *testing.T) {

	resolutionHandler := resolutionHandler()
	response := httptest.NewRecorder()

	invalid := "did:invalid:EiDOQXC2GnoVyHwIRbjhLx_cNc6vmZaS04SZjZdlLLAPRg=="

	// method not supported scenario will result in bad request error
	resolutionHandler.HandleResolveRequest(invalid).WriteResponse(response, runtime.JSONProducer())
	require.Equal(t, http.StatusBadRequest, response.Code)
}

func TestResolutionHandler_HandleResolveRequestError(t *testing.T) {

	resolutionHandler := resolutionHandler()
	response := httptest.NewRecorder()

	testErr := fmt.Errorf("test error")
	resolutionHandler.docResolver = mocks.NewMockDocumentHandler(testErr)

	resolutionHandler.HandleResolveRequest(did).WriteResponse(response, runtime.JSONProducer())
	require.Equal(t, http.StatusInternalServerError, response.Code)

}

func resolutionHandler() *ResolutionHandler {
	return NewResolutionHandler(namespace, coremocks.NewMockProtocolClient(), mocks.NewMockDocumentHandler(nil))
}
