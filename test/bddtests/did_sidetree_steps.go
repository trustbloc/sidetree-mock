/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddtests

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/cucumber/godog"
	jsonpatch "github.com/evanphx/json-patch"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/helper"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"

	"github.com/trustbloc/sidetree-mock/test/bddtests/restclient"
)

var logger = logrus.New()

const (
	didDocNamespace    = "did:sidetree:test"
	testDocumentURL    = "https://localhost:48326/document"
	initialValuesParam = ";initial-values="
	sha2_256           = 18
	recoveryOTP        = "recoveryOTP"
	updateOTP          = "updateOTP"
)

// DIDSideSteps
type DIDSideSteps struct {
	createRequest []byte
	resp          *restclient.HttpRespone
	bddContext    *BDDContext
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

	d.createRequest = req

	d.resp, err = restclient.SendRequest(testDocumentURL, req)
	return err
}

func (d *DIDSideSteps) updateDIDDocument(path, value string) error {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	logger.Infof("update did document: %s", uniqueSuffix)

	req, err := getUpdateRequest(uniqueSuffix, path, value)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(testDocumentURL, req)
	return err
}

func (d *DIDSideSteps) revokeDIDDocument() error {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	logger.Infof("revoke did document: %s", uniqueSuffix)

	req, err := getRevokeRequest(uniqueSuffix)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(testDocumentURL, req)
	return err
}

func (d *DIDSideSteps) resolveDIDDocumentWithID(didDocumentPath, didID string) error {
	var err error
	logger.Infof("resolve did document %s with initial value %s", didDocumentPath, didID)

	d.resp, err = restclient.SendResolveRequest(testDocumentURL + "/" + didDocNamespace + docutil.NamespaceDelimiter + didID + initialValuesParam + docutil.EncodeToString(d.createRequest))
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
		documentHash, err := d.getDID()
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
	did, err := d.getDID()
	if err != nil {
		return err
	}
	d.resp, err = restclient.SendResolveRequest(testDocumentURL + "/" + did)
	return err
}

func (d *DIDSideSteps) resolveDIDDocumentWithInitialValue() error {
	did, err := d.getDID()
	if err != nil {
		return err
	}

	req := testDocumentURL + "/" + did + initialValuesParam + docutil.EncodeToString(d.createRequest)
	d.resp, err = restclient.SendResolveRequest(req)
	return err
}

func getCreateRequest(doc string) ([]byte, error) {
	return helper.NewCreateRequest(&helper.CreateRequestInfo{
		OpaqueDocument:  doc,
		RecoveryKey:     "HEX",
		NextRecoveryOTP: docutil.EncodeToString([]byte(recoveryOTP)),
		NextUpdateOTP:   docutil.EncodeToString([]byte(updateOTP)),
		MultihashCode:   sha2_256,
	})
}

func (d *DIDSideSteps) getDID() (string, error) {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return "", err
	}

	didID := didDocNamespace + docutil.NamespaceDelimiter + uniqueSuffix
	return didID, nil
}

func (d *DIDSideSteps) getUniqueSuffix() (string, error) {
	var createReq model.CreateRequest
	err := json.Unmarshal(d.createRequest, &createReq)
	if err != nil {
		return "", err
	}

	return docutil.CalculateUniqueSuffix(createReq.SuffixData, sha2_256)
}

func getRevokeRequest(did string) ([]byte, error) {
	return helper.NewRevokeRequest(&helper.RevokeRequestInfo{
		DidUniqueSuffix: did,
		RecoveryOTP:     docutil.EncodeToString([]byte(recoveryOTP)),
	})
}

func getUpdateRequest(did, path, value string) ([]byte, error) {
	return helper.NewUpdateRequest(&helper.UpdateRequestInfo{
		DidUniqueSuffix: did,
		UpdateOTP:       docutil.EncodeToString([]byte(updateOTP)),
		Patch:           getUpdatePatch(path, value),
		MultihashCode:   sha2_256,
	})
}

func getUpdatePatch(path, value string) jsonpatch.Patch {
	patchJSON := []byte(fmt.Sprintf(`[{"op": "replace", "path":  "%s", "value": "%s"}]`, path, value))
	jsonPatch, err := jsonpatch.DecodePatch(patchJSON)
	if err != nil {
		panic(err)
	}

	logger.Infof("JSON Patch: %s", patchJSON)

	return jsonPatch
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
	s.Step(`^client sends request to update DID document path "([^"]*)" with value "([^"]*)"$`, d.updateDIDDocument)
	s.Step(`^client sends request to revoke DID document$`, d.revokeDIDDocument)
	s.Step(`^client sends request to resolve DID document with initial value$`, d.resolveDIDDocumentWithInitialValue)
	s.Step(`^we wait (\d+) seconds$`, wait)
}
