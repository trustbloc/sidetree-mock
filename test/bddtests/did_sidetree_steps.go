/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddtests

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/mr-tron/base58"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/helper"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-mock/test/bddtests/restclient"
)

var logger = logrus.New()

const (
	didDocNamespace        = "did:sidetree:test"
	initialStateParam      = "?-sidetree-initial-state="
	testDocumentResolveURL = "https://localhost:48326/sidetree/0.0.1/identifiers"
	testDocumentUpdateURL  = "https://localhost:48326/sidetree/0.0.1/operations"

	sha2_256 = 18
)

const addPublicKeysTemplate = `[
	{
      "id": "%s",
      "purpose": ["general"],
      "type": "JwsVerificationKey2020",
      "jwk": {
        "kty": "EC",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }
  ]`

const removePublicKeysTemplate = `["%s"]`

const addServicesTemplate = `[
    {
      "id": "%s",
      "type": "SecureDataStore",
      "endpoint": "http://hub.my-personal-server.com"
    }
  ]`

const removeServicesTemplate = `["%s"]`

const docTemplate = `{
  "publicKey": [
   {
     "id": "%s",
     "type": "JwsVerificationKey2020",
     "purpose": ["auth", "general"],
     "jwk": %s
   },
   {
     "id": "dual-assertion-gen",
     "type": "Ed25519VerificationKey2018",
     "purpose": ["assertion", "general"],
     "jwk": %s
   }
  ],
  "service": [
	{
	   "id": "oidc",
	   "type": "OpenIdConnectVersion1.0Service",
	   "endpoint": "https://openid.example.com/"
	}, 
	{
	   "id": "didcomm",
	   "type": "did-communication",
	   "endpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/",
	   "recipientKeys": ["%s"],
	   "routingKeys": ["%s"],
	   "priority": 0
	}
  ]
}`

// DIDSideSteps
type DIDSideSteps struct {
	createRequest model.CreateRequest
	recoveryKey   *ecdsa.PrivateKey
	updateKey     *ecdsa.PrivateKey
	resp          *restclient.HttpRespone
	bddContext    *BDDContext
}

// NewDIDSideSteps
func NewDIDSideSteps(context *BDDContext) *DIDSideSteps {
	return &DIDSideSteps{bddContext: context}
}

func (d *DIDSideSteps) createDIDDocument() error {
	var err error

	logger.Info("create did document")

	opaqueDoc, err := d.getOpaqueDocument("createKey")
	if err != nil {
		return err
	}

	req, err := d.getCreateRequest(opaqueDoc)
	if err != nil {
		return err
	}

	err = json.Unmarshal(req, &d.createRequest)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(testDocumentUpdateURL, req)
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

	d.resp, err = restclient.SendRequest(testDocumentUpdateURL, req)
	return err
}

func (d *DIDSideSteps) deactivateDIDDocument() error {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	logger.Infof("deactivate did document: %s", uniqueSuffix)

	req, err := d.getDeactivateRequest(uniqueSuffix)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(testDocumentUpdateURL, req)
	return err
}

func (d *DIDSideSteps) recoverDIDDocument() error {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	logger.Infof("recover did document")

	opaqueDoc, err := d.getOpaqueDocument("recoveryKey")
	if err != nil {
		return err
	}

	req, err := d.getRecoverRequest(opaqueDoc, uniqueSuffix)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(testDocumentUpdateURL, req)
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
	logger.Infof("resolve did document %s with id", didID)

	d.resp, err = restclient.SendResolveRequest(testDocumentResolveURL + "/" + didDocNamespace + docutil.NamespaceDelimiter + didID)
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

		var result document.ResolutionResult
		err = json.Unmarshal(d.resp.Payload, &result)
		if err != nil {
			return err
		}

		err = prettyPrint(&result)
		if err != nil {
			return err
		}

		didDoc := document.DidDocumentFromJSONLDObject(result.Document)

		// perform basic checks on document
		if didDoc.ID() == "" || didDoc.Context()[0] != "https://www.w3.org/ns/did/v1" ||
			!strings.Contains(didDoc.PublicKeys()[0].Controller(), didDoc.ID()) {
			return errors.New("response is not a valid did document")
		}

		logger.Infof("response is a valid did document")
	}

	action := " "
	if !contains {
		action = " NOT"
	}

	if contains && !strings.Contains(string(d.resp.Payload), msg) {
		return errors.Errorf("success resp doesn't contain %s", msg)
	}

	if !contains && strings.Contains(string(d.resp.Payload), msg) {
		return errors.Errorf("success resp should NOT contain %s", msg)
	}

	logger.Infof("passed check that success response MUST%s contain %s", action, msg)

	return nil
}

func (d *DIDSideSteps) resolveDIDDocument() error {
	did, err := d.getDID()
	if err != nil {
		return err
	}
	d.resp, err = restclient.SendResolveRequest(testDocumentResolveURL + "/" + did)
	return err
}

func (d *DIDSideSteps) resolveDIDDocumentWithInitialValue() error {
	did, err := d.getDID()
	if err != nil {
		return err
	}

	initialState := d.createRequest.SuffixData + "." + d.createRequest.Delta

	req := testDocumentResolveURL + "/" + did + initialStateParam + initialState
	d.resp, err = restclient.SendResolveRequest(req)
	return err
}

func (d *DIDSideSteps) getCreateRequest(doc []byte) ([]byte, error) {
	recoveryKey, recoveryCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, err
	}

	d.recoveryKey = recoveryKey

	updateKey, updateCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, err
	}

	d.updateKey = updateKey

	return helper.NewCreateRequest(&helper.CreateRequestInfo{
		OpaqueDocument:     string(doc),
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      sha2_256,
	})
}

func (d *DIDSideSteps) getRecoverRequest(doc []byte, uniqueSuffix string) ([]byte, error) {
	recoveryKey, recoveryCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, err
	}

	updateKey, updateCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, err
	}

	// recovery key and signer passed in are generated during previous operations
	recoveryPubKey, err := pubkey.GetPublicKeyJWK(&d.recoveryKey.PublicKey)
	if err != nil {
		return nil, err
	}

	recoverRequest, err := helper.NewRecoverRequest(&helper.RecoverRequestInfo{
		DidSuffix:          uniqueSuffix,
		OpaqueDocument:     string(doc),
		RecoveryKey:        recoveryPubKey,
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      sha2_256,
		Signer:             ecsigner.New(d.recoveryKey, "ES256", ""), // sign with old signer
	})

	if err != nil {
		return nil, err
	}

	// update recovery and update key for subsequent requests
	d.recoveryKey = recoveryKey
	d.updateKey = updateKey

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
	return docutil.CalculateUniqueSuffix(d.createRequest.SuffixData, sha2_256)
}

func (d *DIDSideSteps) getDeactivateRequest(did string) ([]byte, error) {
	// recovery key and signer passed in are generated during previous operations
	recoveryPubKey, err := pubkey.GetPublicKeyJWK(&d.recoveryKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return helper.NewDeactivateRequest(&helper.DeactivateRequestInfo{
		DidSuffix:   did,
		RecoveryKey: recoveryPubKey,
		Signer:      ecsigner.New(d.recoveryKey, "ES256", ""),
	})
}

func (d *DIDSideSteps) getUpdateRequest(did string, updatePatch patch.Patch) ([]byte, error) {
	updateKey, updateCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, err
	}

	// update key and signer passed in are generated during previous operations
	updatePubKey, err := pubkey.GetPublicKeyJWK(&d.updateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	req, err := helper.NewUpdateRequest(&helper.UpdateRequestInfo{
		DidSuffix:        did,
		UpdateCommitment: updateCommitment,
		UpdateKey:        updatePubKey,
		Patch:            updatePatch,
		MultihashCode:    sha2_256,
		Signer:           ecsigner.New(d.updateKey, "ES256", "update-kid"),
	})

	if err != nil {
		return nil, err
	}

	// update update key for subsequent update requests
	d.updateKey = updateKey

	return req, nil
}

func generateKeyAndCommitment() (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	pubKey, err := pubkey.GetPublicKeyJWK(&key.PublicKey)
	if err != nil {
		return nil, "", err
	}

	c, err := commitment.Calculate(pubKey, sha2_256)
	if err != nil {
		return nil, "", err
	}

	return key, c, nil
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
	// create general + auth JWS verification key
	jwsPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	jwsPubKey, err := getPubKey(&jwsPrivateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	// create general + assertion ed25519 verification key
	ed25519PulicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	ed25519PubKey, err := getPubKey(ed25519PulicKey)
	if err != nil {
		return nil, err
	}

	recipientKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	routingKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	data := fmt.Sprintf(
		docTemplate,
		keyID, jwsPubKey, ed25519PubKey, base58.Encode(recipientKey), base58.Encode(routingKey))

	doc, err := document.FromBytes([]byte(data))
	if err != nil {
		return nil, err
	}

	return doc.Bytes()
}

func getPubKey(pubKey interface{}) (string, error) {
	publicKey, err := pubkey.GetPublicKeyJWK(pubKey)
	if err != nil {
		return "", err
	}

	opsPubKeyBytes, err := json.Marshal(publicKey)
	if err != nil {
		return "", err
	}

	return string(opsPubKeyBytes), nil
}

func (d *DIDSideSteps) processInteropRequest(path string) error {
	var err error

	logger.Infof("processing interop request from '%s'", path)

	reqBytes, err := readInteropRequest(path)
	if err != nil {
		return err
	}

	var req model.CreateRequest
	err = json.Unmarshal(reqBytes, &req)
	if err != nil {
		return err
	}

	if req.Operation == model.OperationTypeCreate {
		d.createRequest = req
	}

	d.resp, err = restclient.SendRequest(testDocumentUpdateURL, reqBytes)
	return err
}

func (d *DIDSideSteps) processInteropResolveWithInitialValue() error {
	var err error

	d.resp, err = restclient.SendResolveRequest(testDocumentResolveURL + "/" + interopResolveDidWithInitialState)
	return err
}

func readInteropRequest(requestPath string) ([]byte, error) {
	r, _ := os.Open(requestPath)
	return ioutil.ReadAll(r)
}

func wait(seconds int) error {
	logger.Infof("Waiting [%d] seconds\n", seconds)
	time.Sleep(time.Duration(seconds) * time.Second)
	return nil
}

func prettyPrint(result *document.ResolutionResult) error {
	b, err := json.MarshalIndent(result, "", " ")
	if err != nil {
		return err
	}

	logger.Info(string(b))

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
	s.Step(`^client sends request to deactivate DID document$`, d.deactivateDIDDocument)
	s.Step(`^client sends request to recover DID document$`, d.recoverDIDDocument)
	s.Step(`^client sends request to resolve DID document with initial value$`, d.resolveDIDDocumentWithInitialValue)
	s.Step(`^client sends interop operation request from "([^"]*)"$`, d.processInteropRequest)
	s.Step(`^client sends interop resolve with initial value request$`, d.processInteropResolveWithInitialValue)
	s.Step(`^we wait (\d+) seconds$`, wait)
}

const interopResolveDidWithInitialState = `did:sidetree:test:EiBFsUlzmZ3zJtSFeQKwJNtngjmB51ehMWWDuptf9b4Bag?-sidetree-initial-state=eyJkZWx0YV9oYXNoIjoiRWlCWE00b3RMdVAyZkc0WkE3NS1hbnJrV1ZYMDYzN3hadE1KU29Lb3AtdHJkdyIsInJlY292ZXJ5X2NvbW1pdG1lbnQiOiJFaUM4RzRJZGJEN0Q0Q281N0dqTE5LaG1ERWFicnprTzF3c0tFOU1RZVV2T2d3In0.eyJ1cGRhdGVfY29tbWl0bWVudCI6IkVpQ0lQY1hCempqUWFKVUljUjUyZXVJMHJJWHpoTlpfTWxqc0tLOXp4WFR5cVEiLCJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljX2tleXMiOlt7ImlkIjoic2lnbmluZ0tleSIsInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkiLCJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoieTlrenJWQnFYeDI0c1ZNRVFRazRDZS0wYnFaMWk1VHd4bGxXQ2t6QTd3VSIsInkiOiJjMkpIeFFxVVV0eVdJTEFJaWNtcEJHQzQ3UGdtSlQ0NjV0UG9jRzJxMThrIn0sInB1cnBvc2UiOlsiYXV0aCIsImdlbmVyYWwiXX1dLCJzZXJ2aWNlX2VuZHBvaW50cyI6W3siaWQiOiJzZXJ2aWNlRW5kcG9pbnRJZDEyMyIsInR5cGUiOiJzb21lVHlwZSIsImVuZHBvaW50IjoiaHR0cHM6Ly93d3cudXJsLmNvbSJ9XX19XX0`
