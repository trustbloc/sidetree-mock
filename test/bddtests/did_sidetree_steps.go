/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddtests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/helper"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
	"github.com/trustbloc/sidetree-core-go/pkg/util"
	"github.com/trustbloc/sidetree-mock/test/bddtests/restclient"
)

var logger = logrus.New()

const (
	didDocNamespace     = "did:sidetree:test"
	testDocumentURL     = "https://localhost:48326/document"
	initialValuesParam  = ";initial-values="
	sha2_256            = 18
	recoveryRevealValue = "recoveryOTP"
	updateRevealValue   = "updateOTP"
)

const addPublicKeysTemplate = `[
	{
      "id": "%s",
      "usage": ["ops"],
      "type": "Secp256k1VerificationKey2018",
      "publicKeyHex": "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71"
    }
  ]`

const removePublicKeysTemplate = `["%s"]`

const addServicesTemplate = `[
    {
      "id": "%s",
      "type": "SecureDataStore",
      "serviceEndpoint": "http://hub.my-personal-server.com"
    }
  ]`

const removeServicesTemplate = `["%s"]`

const docTemplate = `{
  "publicKey": [
	{
  		"id": "%s",
  		"type": "JwsVerificationKey2020",
		"usage": ["ops"],
  		"publicKeyJwk": %s
	}
  ],
  "service": [
	{
	   "id": "did:example:123456789abcdefghi#oidc",
	   "type": "OpenIdConnectVersion1.0Service",
	   "serviceEndpoint": "https://openid.example.com/"
	}, 
	{
	   "id": "did:example:123456789abcdefghi#hub",
	   "type": "HubService",
	   "serviceEndpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/"
	}
  ]
}`

// DIDSideSteps
type DIDSideSteps struct {
	createRequest     []byte
	recoveryKeySigner helper.Signer
	updateKeySigner   helper.Signer
	resp              *restclient.HttpRespone
	bddContext        *BDDContext
}

// NewDIDSideSteps
func NewDIDSideSteps(context *BDDContext) *DIDSideSteps {
	return &DIDSideSteps{bddContext: context}
}

func (d *DIDSideSteps) createDIDDocument() error {
	var err error

	logger.Info("create did document")

	opaqueDoc, err := d.getOpaqueDocument("#key1")
	if err != nil {
		return err
	}

	req, err := d.getCreateRequest(opaqueDoc)
	if err != nil {
		return err
	}

	d.createRequest = req

	d.resp, err = restclient.SendRequest(testDocumentURL, req)
	return err
}

func (d *DIDSideSteps) updateDIDDocument(patch patch.Patch) error {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	logger.Infof("update did document: %s", uniqueSuffix)

	req, err := d.getUpdateRequest(uniqueSuffix, patch)
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

	req, err := d.getRevokeRequest(uniqueSuffix)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(testDocumentURL, req)
	return err
}

func (d *DIDSideSteps) recoverDIDDocument() error {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	logger.Infof("recover did document")

	opaqueDoc, err := d.getOpaqueDocument("#recoveryKey")
	if err != nil {
		return err
	}

	req, err := d.getRecoverRequest(opaqueDoc, uniqueSuffix)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(testDocumentURL, req)
	return err
}

func (d *DIDSideSteps) updateDIDDocumentWithJSONPatch(path, value string) error {
	patch, err := getJSONPatch(path, value)
	if err != nil {
		return err
	}

	return d.updateDIDDocument(patch)
}

func (d *DIDSideSteps) addPublicKeyToDIDDocument(keyID string) error {
	patch, err := getAddPublicKeysPatch(keyID)
	if err != nil {
		return err
	}

	return d.updateDIDDocument(patch)
}

func (d *DIDSideSteps) removePublicKeyFromDIDDocument(keyID string) error {
	patch, err := getRemovePublicKeysPatch(keyID)
	if err != nil {
		return err
	}

	return d.updateDIDDocument(patch)
}

func (d *DIDSideSteps) addServiceEndpointToDIDDocument(keyID string) error {
	patch, err := getAddServiceEndpointsPatch(keyID)
	if err != nil {
		return err
	}

	return d.updateDIDDocument(patch)
}

func (d *DIDSideSteps) removeServiceEndpointsFromDIDDocument(keyID string) error {
	patch, err := getRemoveServiceEndpointsPatch(keyID)
	if err != nil {
		return err
	}

	return d.updateDIDDocument(patch)
}

func (d *DIDSideSteps) resolveDIDDocumentWithID(didID string) error {
	var err error
	logger.Infof("resolve did document %s with initial value", didID)

	d.resp, err = restclient.SendResolveRequest(testDocumentURL + "/" + didDocNamespace + docutil.NamespaceDelimiter + didID + initialValuesParam + docutil.EncodeToString(d.createRequest))
	return err
}

func (d *DIDSideSteps) checkErrorResp(errorMsg string) error {
	if !strings.Contains(d.resp.ErrorMsg, errorMsg) {
		return errors.Errorf("error resp %s doesn't contain %s", d.resp.ErrorMsg, errorMsg)
	}
	return nil
}

func (d *DIDSideSteps) checkSuccessRespContains(msg string) error {
	return d.checkSuccessResp(msg, true)
}

func (d *DIDSideSteps) checkSuccessRespDoesntContain(msg string) error {
	return d.checkSuccessResp(msg, false)
}

func (d *DIDSideSteps) checkSuccessResp(msg string, contains bool) error {
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

	action := " "
	if !contains {
		action = " NOT"
	}

	logger.Infof("check success resp %s MUST%s contain %s", string(d.resp.Payload), action, msg)
	if contains && !strings.Contains(string(d.resp.Payload), msg) {
		return errors.Errorf("success resp %s doesn't contain %s", d.resp.Payload, msg)
	}

	if !contains && strings.Contains(string(d.resp.Payload), msg) {
		return errors.Errorf("success resp %s should NOT contain %s", d.resp.Payload, msg)
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

func (d *DIDSideSteps) getCreateRequest(doc []byte) ([]byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	d.recoveryKeySigner = util.NewECDSASigner(privateKey, "ES256", "recovery")
	if err != nil {
		return nil, err
	}

	recoveryPublicKey, err := util.GetECPublicKey(privateKey)
	if err != nil {
		return nil, err
	}

	return helper.NewCreateRequest(&helper.CreateRequestInfo{
		OpaqueDocument:          string(doc),
		RecoveryKey:             recoveryPublicKey,
		NextRecoveryRevealValue: []byte(recoveryRevealValue),
		NextUpdateRevealValue:   []byte(updateRevealValue),
		MultihashCode:           sha2_256,
	})
}

func (d *DIDSideSteps) getRecoverRequest(doc []byte, uniqueSuffix string) ([]byte, error) {
	newPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	newRecoveryPublicKey, err := util.GetECPublicKey(newPrivateKey)
	if err != nil {
		return nil, err
	}

	recoverRequest, err := helper.NewRecoverRequest(&helper.RecoverRequestInfo{
		DidUniqueSuffix:         uniqueSuffix,
		OpaqueDocument:          string(doc),
		RecoveryKey:             newRecoveryPublicKey,
		RecoveryRevealValue:     []byte(recoveryRevealValue),
		NextRecoveryRevealValue: []byte(recoveryRevealValue),
		NextUpdateRevealValue:   []byte(updateRevealValue),
		MultihashCode:           sha2_256,
		Signer:                  d.recoveryKeySigner, // sign with old signer
	})

	if err != nil {
		return nil, err
	}

	// update recovery key singer for subsequent requests
	d.recoveryKeySigner = util.NewECDSASigner(newPrivateKey, "ES256", "recovery")

	return recoverRequest, nil
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

func (d *DIDSideSteps) getRevokeRequest(did string) ([]byte, error) {
	return helper.NewRevokeRequest(&helper.RevokeRequestInfo{
		DidUniqueSuffix:     did,
		RecoveryRevealValue: []byte(recoveryRevealValue),
		Signer:              d.recoveryKeySigner,
	})
}

func (d *DIDSideSteps) getUpdateRequest(did string, updatePatch patch.Patch) ([]byte, error) {
	return helper.NewUpdateRequest(&helper.UpdateRequestInfo{
		DidUniqueSuffix:       did,
		UpdateRevealValue:     []byte(updateRevealValue),
		NextUpdateRevealValue: []byte(updateRevealValue),
		Patch:                 updatePatch,
		MultihashCode:         sha2_256,
		Signer:                d.updateKeySigner,
	})
}

func getJSONPatch(path, value string) (patch.Patch, error) {
	patches := fmt.Sprintf(`[{"op": "replace", "path":  "%s", "value": "%s"}]`, path, value)
	logger.Infof("creating JSON patch: %s", patches)
	return patch.NewJSONPatch(patches)
}

func getAddPublicKeysPatch(keyID string) (patch.Patch, error) {
	addPubKeys := fmt.Sprintf(addPublicKeysTemplate, keyID)
	logger.Infof("creating add public keys patch: %s", addPubKeys)
	return patch.NewAddPublicKeysPatch(addPubKeys)
}

func getRemovePublicKeysPatch(keyID string) (patch.Patch, error) {
	removePubKeys := fmt.Sprintf(removePublicKeysTemplate, keyID)
	logger.Infof("creating remove public keys patch: %s", removePubKeys)
	return patch.NewRemovePublicKeysPatch(removePubKeys)
}

func getAddServiceEndpointsPatch(svcID string) (patch.Patch, error) {
	addServices := fmt.Sprintf(addServicesTemplate, svcID)
	logger.Infof("creating add service endpoints patch: %s", addServices)
	return patch.NewAddServiceEndpointsPatch(addServices)
}

func getRemoveServiceEndpointsPatch(keyID string) (patch.Patch, error) {
	removeServices := fmt.Sprintf(removeServicesTemplate, keyID)
	logger.Infof("creating remove service endpoints patch: %s", removeServices)
	return patch.NewRemoveServiceEndpointsPatch(removeServices)
}

func (d *DIDSideSteps) getOpaqueDocument(keyID string) ([]byte, error) {
	// generate private key that will be used for document updates and
	// insert public key that correspond to this private key into document (JWK format)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	publicKey, err := util.GetECPublicKey(privateKey)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, err := json.Marshal(publicKey)
	if err != nil {
		return nil, err
	}

	data := fmt.Sprintf(docTemplate, keyID, string(publicKeyBytes))

	doc, err := document.FromBytes([]byte(data))
	if err != nil {
		return nil, err
	}

	d.updateKeySigner = util.NewECDSASigner(privateKey, "ES256", keyID)

	return doc.Bytes()
}

func wait(seconds int) error {
	logger.Infof("Waiting [%d] seconds\n", seconds)
	time.Sleep(time.Duration(seconds) * time.Second)
	return nil
}

// RegisterSteps registers did sidetree steps
func (d *DIDSideSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^check error response contains "([^"]*)"$`, d.checkErrorResp)
	s.Step(`^client sends request to create DID document$`, d.createDIDDocument)
	s.Step(`^check success response contains "([^"]*)"$`, d.checkSuccessRespContains)
	s.Step(`^check success response does NOT contain "([^"]*)"$`, d.checkSuccessRespDoesntContain)
	s.Step(`^client sends request to resolve DID document$`, d.resolveDIDDocument)
	s.Step(`^client sends request to update DID document path "([^"]*)" with value "([^"]*)"$`, d.updateDIDDocumentWithJSONPatch)
	s.Step(`^client sends request to add public key with ID "([^"]*)" to DID document$`, d.addPublicKeyToDIDDocument)
	s.Step(`^client sends request to remove public key with ID "([^"]*)" from DID document$`, d.removePublicKeyFromDIDDocument)
	s.Step(`^client sends request to add service endpoint with ID "([^"]*)" to DID document$`, d.addServiceEndpointToDIDDocument)
	s.Step(`^client sends request to remove service endpoint with ID "([^"]*)" from DID document$`, d.removeServiceEndpointsFromDIDDocument)
	s.Step(`^client sends request to revoke DID document$`, d.revokeDIDDocument)
	s.Step(`^client sends request to recover DID document$`, d.recoverDIDDocument)
	s.Step(`^client sends request to resolve DID document with initial value$`, d.resolveDIDDocumentWithInitialValue)
	s.Step(`^we wait (\d+) seconds$`, wait)
}
