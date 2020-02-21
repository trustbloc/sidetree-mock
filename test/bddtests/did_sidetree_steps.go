/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddtests

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/DATA-DOG/godog"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
	"github.com/trustbloc/sidetree-mock/test/bddtests/restclient"
)

var logger = logrus.New()

const (
	didDocNamespace    = "did:sidetree"
	testDocumentURL    = "http://localhost:48326/document"
	initialValuesParam = ";initial-values="
	sha2_256           = 18
	updateOTP          = "updateOTP"
	recoveryOTP        = "recoveryOTP"
)

// DIDSideSteps
type DIDSideSteps struct {
	encodedCreatePayload string
	encodedDoc           string
	resp                 *restclient.HttpRespone
	bddContext           *BDDContext
}

// NewDIDSideSteps
func NewDIDSideSteps(context *BDDContext) *DIDSideSteps {
	return &DIDSideSteps{bddContext: context}
}

func (d *DIDSideSteps) createDIDDocument(didDocumentPath string) error {
	return d.createDIDDocumentWithID(didDocumentPath, "")
}

func (d *DIDSideSteps) createDIDDocumentWithID(didDocumentPath, didID string) error {
	var err error

	logger.Infof("create did document %s with didID %s", didDocumentPath, didID)

	encodedDidDoc := encodeDidDocument(didDocumentPath, didID)
	payload, err := getCreatePayload(encodedDidDoc)
	if err != nil {
		return err
	}

	req := request("ES256K", "#key1", payload, "")

	d.encodedCreatePayload = payload
	d.encodedDoc = encodedDidDoc

	d.resp, err = restclient.SendRequest(testDocumentURL, req)
	return err
}

func (d *DIDSideSteps) deleteDIDDocument() error {
	uniqueSuffix, err := docutil.CalculateUniqueSuffix(d.encodedCreatePayload, sha2_256)
	if err != nil {
		return err
	}

	logger.Infof("delete did document: %s", uniqueSuffix)

	payload, err := getDeletePayload(uniqueSuffix)
	if err != nil {
		return err
	}

	req := request("ES256K", "#key1", payload, "")

	d.resp, err = restclient.SendRequest(testDocumentURL, req)
	return err
}

func (d *DIDSideSteps) resolveDIDDocumentWithID(didDocumentPath, didID string) error {
	var err error
	logger.Infof("resolve did document %s with initial value %s", didDocumentPath, didID)

	d.encodedDoc = encodeDidDocument(didDocumentPath, didID)
	d.resp, err = restclient.SendResolveRequest(testDocumentURL + "/" + didDocNamespace + docutil.NamespaceDelimiter + didID + initialValuesParam + d.encodedDoc)
	return err
}

func (d *DIDSideSteps) checkErrorResp(errorMsg string) error {
	if !strings.Contains(d.resp.ErrorMsg, errorMsg) {
		return errors.Errorf("error resp %s doesn't contain %s", d.resp.ErrorMsg, errorMsg)
	}
	return nil
}

func (d *DIDSideSteps) checkSuccessResp(msg string) error {
	if d.resp.ErrorMsg != "" {
		return errors.Errorf("error resp %s", d.resp.ErrorMsg)
	}

	if msg == "#didDocumentHash" {
		documentHash, err := docutil.CalculateID(didDocNamespace, d.encodedCreatePayload, sha2_256)
		if err != nil {
			return err
		}
		msg = strings.Replace(msg, "#didDocumentHash", documentHash, -1)
	}
	logger.Infof("check success resp %s contain %s", string(d.resp.Payload), msg)
	if !strings.Contains(string(d.resp.Payload), msg) {
		return errors.Errorf("success resp %s doesn't contain %s", d.resp.Payload, msg)
	}
	return nil
}

func (d *DIDSideSteps) resolveDIDDocument() error {
	did, err := docutil.CalculateID(didDocNamespace, d.encodedCreatePayload, sha2_256)
	if err != nil {
		return err
	}
	d.resp, err = restclient.SendResolveRequest(testDocumentURL + "/" + did)
	return err
}

func (d *DIDSideSteps) resolveDIDDocumentWithInitialValue() error {
	did, err := docutil.CalculateID(didDocNamespace, d.encodedCreatePayload, sha2_256)
	if err != nil {
		return err
	}
	d.resp, err = restclient.SendResolveRequest(testDocumentURL + "/" + did + initialValuesParam + d.encodedDoc)
	return err
}

func request(alg, kid, payload, signature string) *model.Request {
	header := &model.Header{
		Alg: alg,
		Kid: kid,
	}
	req := &model.Request{
		Protected: header,
		Payload:   payload,
		Signature: signature}
	return req
}

func getCreatePayload(encodedDoc string) (string, error) {
	nextRecoveryOTPHash, err := docutil.ComputeMultihash(sha2_256, []byte(recoveryOTP))
	if err != nil {
		return "", err
	}

	nextUpdateOTPHash, err := docutil.ComputeMultihash(sha2_256, []byte(updateOTP))
	if err != nil {
		return "", err
	}

	payload, err := json.Marshal(
		struct {
			Operation           model.OperationType `json:"type"`
			DIDDocument         string              `json:"didDocument"`
			NextUpdateOTPHash   string              `json:"nextUpdateOtpHash"`
			NextRecoveryOTPHash string              `json:"nextRecoveryOtpHash"`
		}{
			Operation:           model.OperationTypeCreate,
			DIDDocument:         encodedDoc,
			NextUpdateOTPHash:   base64.URLEncoding.EncodeToString(nextUpdateOTPHash),
			NextRecoveryOTPHash: base64.URLEncoding.EncodeToString(nextRecoveryOTPHash),
		})

	if err != nil {
		return "", err
	}

	return docutil.EncodeToString(payload), nil
}

func getDeletePayload(did string) (string, error) {
	payload, err := json.Marshal(
		struct {
			Operation       model.OperationType `json:"type"`
			DidUniqueSuffix string              `json:"didUniqueSuffix"`
			RecoveryOTP     string              `json:"recoveryOtp"`
		}{
			Operation:       model.OperationTypeDelete,
			DidUniqueSuffix: did,
			RecoveryOTP:     base64.URLEncoding.EncodeToString([]byte(recoveryOTP)),
		})

	if err != nil {
		return "", err
	}

	return docutil.EncodeToString(payload), nil
}

func encodeDidDocument(didDocumentPath, didID string) string {
	r, _ := os.Open(didDocumentPath)
	data, _ := ioutil.ReadAll(r)
	doc, _ := document.FromBytes(data)
	if didID != "" {
		doc["id"] = didID
	}
	// add new key to make the document unique
	doc["unique"] = generateUUID()
	bytes, _ := doc.Bytes()
	return docutil.EncodeToString(bytes)
}

func wait(seconds int) error {
	logger.Infof("Waiting [%d] seconds\n", seconds)
	time.Sleep(time.Duration(seconds) * time.Second)
	return nil
}

// RegisterSteps registers did sidetree steps
func (d *DIDSideSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^client sends request to create DID document "([^"]*)" with ID "([^"]*)"$`, d.createDIDDocumentWithID)
	s.Step(`^client sends request to resolve DID document "([^"]*)" with ID "([^"]*)"$`, d.resolveDIDDocumentWithID)
	s.Step(`^check error response contains "([^"]*)"$`, d.checkErrorResp)
	s.Step(`^client sends request to create DID document "([^"]*)"$`, d.createDIDDocument)
	s.Step(`^check success response contains "([^"]*)"$`, d.checkSuccessResp)
	s.Step(`^client sends request to resolve DID document$`, d.resolveDIDDocument)
	s.Step(`^client sends request to delete DID document$`, d.deleteDIDDocument)
	s.Step(`^client sends request to resolve DID document with initial value$`, d.resolveDIDDocumentWithInitialValue)
	s.Step(`^we wait (\d+) seconds$`, wait)
}
