/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	coremocks "github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/diddochandler"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/dochandler"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/client"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/model"

	"github.com/trustbloc/sidetree-mock/pkg/mocks"
)

const (
	url       = "localhost:8080"
	clientURL = "http://" + url

	didDocNamespace = "did:sidetree"
	basePath        = "/sidetree/0.0.1"

	sha2_256        = 18
	sampleNamespace = "sample:sidetree"
	samplePath      = "/sample"
)

var (
	baseResolvePath = basePath + "/identifiers"
	baseUpdatePath  = basePath + "/operations"
)

func TestServer_Start(t *testing.T) {
	didDocHandler := coremocks.NewMockDocumentHandler().WithNamespace(didDocNamespace)
	sampleDocHandler := coremocks.NewMockDocumentHandler().WithNamespace(sampleNamespace)

	pcp := mocks.NewMockProtocolClientProvider()
	pc, err := pcp.ForNamespace(coremocks.DefaultNS)
	require.NoError(t, err)

	s := New(url,
		"",
		"",
		"tk1",
		diddochandler.NewUpdateHandler(basePath, didDocHandler, pc),
		diddochandler.NewResolveHandler(basePath, didDocHandler),
		newSampleUpdateHandler(sampleDocHandler, pc),
		newSampleResolveHandler(sampleDocHandler),
	)
	require.NoError(t, s.Start())
	require.Error(t, s.Start())

	// Wait for the service to start
	time.Sleep(time.Second)

	req, err := getCreateRequest()
	require.NoError(t, err)

	var createReq model.CreateRequest
	err = json.Unmarshal(req, &createReq)
	require.NoError(t, err)

	didID, err := docutil.CalculateID(didDocNamespace, createReq.SuffixData, sha2_256)
	require.NoError(t, err)

	sampleID, err := docutil.CalculateID(sampleNamespace, createReq.SuffixData, sha2_256)
	require.NoError(t, err)

	authorizationHdr := "Bearer " + "tk1"

	t.Run("Create DID doc failed ", func(t *testing.T) {
		resp, err := httpPut(t, clientURL+baseUpdatePath, "wrongToken", req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Unauthorised")
		require.Nil(t, resp)

	})

	t.Run("Create DID doc", func(t *testing.T) {
		resp, err := httpPut(t, clientURL+baseUpdatePath, authorizationHdr, req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		var result document.ResolutionResult
		require.NoError(t, json.Unmarshal(resp, &result))
		require.Equal(t, didID, result.Document["id"])
	})
	t.Run("Resolve DID doc", func(t *testing.T) {
		authorizationHdr := "Bearer " + "tk1"
		resp, err := httpGet(t, clientURL+baseResolvePath+"/"+didID, authorizationHdr)
		require.NoError(t, err)
		require.NotNil(t, resp)

		var result document.ResolutionResult
		require.NoError(t, json.Unmarshal(resp, &result))
		require.Equal(t, didID, result.Document["id"])
	})
	t.Run("Create Sample doc", func(t *testing.T) {
		resp, err := httpPut(t, clientURL+samplePath, authorizationHdr, req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		var result document.ResolutionResult
		require.NoError(t, json.Unmarshal(resp, &result))
		require.Equal(t, sampleID, result.Document["id"])
	})
	t.Run("Resolve Sample doc", func(t *testing.T) {
		resp, err := httpGet(t, clientURL+samplePath+"/"+sampleID, authorizationHdr)
		require.NoError(t, err)
		require.NotNil(t, resp)

		var result document.ResolutionResult
		require.NoError(t, json.Unmarshal(resp, &result))
		require.Equal(t, sampleID, result.Document["id"])
	})
	t.Run("Stop", func(t *testing.T) {
		require.NoError(t, s.Stop(context.Background()))
		require.Error(t, s.Stop(context.Background()))
	})
}

// httpPut sends a regular POST request to the sidetree-node
// - If post request has operation "create" then return sidetree document else no response
func httpPut(t *testing.T, url, authorizationHdr string, req []byte) ([]byte, error) {
	client := &http.Client{}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(req))
	require.NoError(t, err)

	httpReq.Header.Set("Content-Type", "application/json")

	if authorizationHdr != "" {
		httpReq.Header.Add("Authorization", authorizationHdr)
	}

	resp, err := invokeWithRetry(
		func() (response *http.Response, e error) {
			return client.Do(httpReq)
		},
	)
	require.NoError(t, err)
	return handleHttpResp(t, resp)
}

// httpGet send a regular GET request to the sidetree-node and expects 'side tree document' argument as a response
func httpGet(t *testing.T, url, authorizationHdr string) ([]byte, error) {
	client := &http.Client{}

	httpReq, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)

	if authorizationHdr != "" {
		httpReq.Header.Add("Authorization", authorizationHdr)
	}

	resp, err := invokeWithRetry(
		func() (response *http.Response, e error) {
			return client.Do(httpReq)
		},
	)
	require.NoError(t, err)
	return handleHttpResp(t, resp)
}

func handleHttpResp(t *testing.T, resp *http.Response) ([]byte, error) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}

	if status := resp.StatusCode; status != http.StatusOK {
		return nil, fmt.Errorf(string(body))
	}
	return body, nil
}

func invokeWithRetry(invoke func() (*http.Response, error)) (*http.Response, error) {
	remainingAttempts := 20
	for {
		resp, err := invoke()
		if err == nil {
			return resp, err
		}
		remainingAttempts--
		if remainingAttempts == 0 {
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type sampleUpdateHandler struct {
	*dochandler.UpdateHandler
}

func newSampleUpdateHandler(processor dochandler.Processor, pc protocol.Client) *sampleUpdateHandler {
	return &sampleUpdateHandler{
		UpdateHandler: dochandler.NewUpdateHandler(processor, pc),
	}
}

// Path returns the context path
func (h *sampleUpdateHandler) Path() string {
	return samplePath
}

// Method returns the HTTP method
func (h *sampleUpdateHandler) Method() string {
	return http.MethodPost
}

// Handler returns the handler
func (h *sampleUpdateHandler) Handler() common.HTTPRequestHandler {
	return h.Update
}

// Update creates/updates the document
func (o *sampleUpdateHandler) Update(rw http.ResponseWriter, req *http.Request) {
	o.UpdateHandler.Update(rw, req)
}

type sampleResolveHandler struct {
	*dochandler.ResolveHandler
}

func newSampleResolveHandler(resolver dochandler.Resolver) *sampleResolveHandler {
	return &sampleResolveHandler{
		ResolveHandler: dochandler.NewResolveHandler(resolver),
	}
}

// Path returns the context path
func (h *sampleResolveHandler) Path() string {
	return samplePath + "/{id}"
}

// Method returns the HTTP method
func (h *sampleResolveHandler) Method() string {
	return http.MethodGet
}

// Handler returns the handler
func (h *sampleResolveHandler) Handler() common.HTTPRequestHandler {
	return h.Resolve
}

func getCreateRequest() ([]byte, error) {
	updateKey := &jws.JWK{
		Crv: "crv",
		Kty: "kty",
		X:   "x",
	}

	recoveryKey := &jws.JWK{
		Crv: "crv",
		Kty: "kty",
		X:   "x",
		Y:   "y",
	}

	updateCommitment, err := commitment.GetCommitment(updateKey, sha2_256)
	if err != nil {
		return nil, err
	}

	recoveryCommitment, err := commitment.GetCommitment(recoveryKey, sha2_256)
	if err != nil {
		return nil, err
	}

	info := &client.CreateRequestInfo{
		OpaqueDocument:     validDoc,
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      sha2_256,
	}
	return client.NewCreateRequest(info)
}

const validDoc = `{
	"publicKey": [{
		"id": "key-1",
		"purposes": ["authentication"],
		"type": "JsonWebKey2020",
		"publicKeyJwk": {
			"kty": "EC",
			"crv": "P-256K",
			"x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
			"y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
		}
	}]
}`
