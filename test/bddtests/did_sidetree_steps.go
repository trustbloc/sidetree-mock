/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddtests

import (
	"encoding/base64"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/helper"
	"github.com/trustbloc/sidetree-mock/test/bddtests/restclient"
)

var logger = logrus.New()

const (
	didDocNamespace    = "did:sidetree:test"
	testDocumentURL    = "http://localhost:48326/document"
	initialValuesParam = ";initial-values="
	sha2_256           = 18
	updateOTP          = "updateOTP"
	recoveryOTP        = "recoveryOTP"
)

// DIDSideSteps
type DIDSideSteps struct {
	encodedCreatePayload string
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

	opaqueDoc := getOpaqueDocument(didDocumentPath, didID)
	req, err := getCreateRequest(opaqueDoc)
	if err != nil {
		return err
	}

	d.encodedCreatePayload = docutil.EncodeToString(req)

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

	req, err := getRequest(payload)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(testDocumentURL, req)
	return err
}

func (d *DIDSideSteps) resolveDIDDocumentWithID(didDocumentPath, didID string) error {
	var err error
	logger.Infof("resolve did document %s with initial value %s", didDocumentPath, didID)

	d.resp, err = restclient.SendResolveRequest(testDocumentURL + "/" + didDocNamespace + docutil.NamespaceDelimiter + didID + initialValuesParam + d.encodedCreatePayload)
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
		didDoc, err := document.DidDocumentFromBytes(d.resp.Payload)
		if err != nil {
			return err
		}

		// perform basic checks on document
		if didDoc.ID() == "" || didDoc.Context()[0] != "https://w3id.org/did/v1" ||
			!strings.Contains(didDoc.PublicKeys()[0].Controller(), didDoc.ID()) {
			return errors.New("response is not a valid did document")
		}

		logger.Infof("response is a valid did document")
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
	d.resp, err = restclient.SendResolveRequest(testDocumentURL + "/" + did + initialValuesParam + d.encodedCreatePayload)
	return err
}

func getCreateRequest(doc string) ([]byte, error) {
	return helper.NewCreateRequest(&helper.CreateRequestInfo{
		OpaqueDocument:  doc,
		RecoveryKey:     "recoveryKey",
		NextRecoveryOTP: recoveryOTP,
		MultihashCode:   sha2_256,
	})
}

func getRequest(payload string) ([]byte, error) {
	return helper.NewSignedRequest(&helper.SignedRequestInfo{
		Payload:   payload,
		Algorithm: "alg",
		KID:       "kid",
		Signature: "signature",
	})
}

func getDeletePayload(did string) (string, error) {
	return helper.NewDeletePayload(&helper.DeletePayloadInfo{
		DidUniqueSuffix: did,
		RecoveryOTP:     base64.URLEncoding.EncodeToString([]byte(recoveryOTP)),
	})
}

func getOpaqueDocument(didDocumentPath, didID string) string {
	r, _ := os.Open(didDocumentPath)
	data, _ := ioutil.ReadAll(r)
	doc, _ := document.FromBytes(data)
	if didID != "" {
		doc["id"] = didID
	}
	// add new key to make the document unique
	doc["unique"] = generateUUID()
	bytes, _ := doc.Bytes()
	return string(bytes)
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
