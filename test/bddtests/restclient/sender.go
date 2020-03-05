/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restclient

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
)

type HttpRespone struct {
	Payload  []byte
	ErrorMsg string
}

// SendRequest sends a regular POST request to the sidetree-mock
// - If post request has operation "create" then return sidetree document else no response
func SendRequest(url string, req []byte) (*HttpRespone, error) {
	resp, err := sendHTTPRequest(url, req)
	if err != nil {
		return nil, err
	}
	return handleHttpResp(resp)
}

// SendResolveRequest send a regular GET request to the sidetree-mock and expects 'side tree document' argument as a response
func SendResolveRequest(url string) (*HttpRespone, error) {
	client := &http.Client{}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	return handleHttpResp(resp)
}

func handleHttpResp(resp *http.Response) (*HttpRespone, error) {
	gotBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}
	if status := resp.StatusCode; status != http.StatusOK {
		return &HttpRespone{ErrorMsg: string(gotBody)}, nil
	}
	return &HttpRespone{Payload: gotBody}, nil
}

func sendHTTPRequest(url string, request []byte) (*http.Response, error) {
	client := &http.Client{}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(request))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	return client.Do(httpReq)
}
