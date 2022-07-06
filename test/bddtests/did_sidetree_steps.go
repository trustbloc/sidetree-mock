/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddtests

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/trustbloc/sidetree-mock/test/bddtests/jsondiff"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/encoder"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/client"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/model"
	"github.com/trustbloc/sidetree-mock/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/sidetree-mock/test/bddtests/restclient"
)

var logger = logrus.New()

const (
	didDocNamespace = "did:sidetree"

	initialStateSeparator = ":"

	sha2_256 = 18
)

const addPublicKeysTemplate = `[
	{
      "id": "%s",
      "purposes": ["authentication"],
      "type": "JsonWebKey2020",
      "publicKeyJwk": {
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
      "serviceEndpoint": "http://hub.my-personal-server.com"
    }
  ]`

const removeServicesTemplate = `["%s"]`

const docTemplate = `{
  "publicKey": [
   {
     "id": "%s",
     "type": "JsonWebKey2020",
     "purposes": ["authentication"],
     "publicKeyJwk": %s
   },
   {
     "id": "auth",
     "type": "Ed25519VerificationKey2018",
     "purposes": ["assertionMethod"],
     "publicKeyJwk": %s
   }
  ],
  "service": [
	{
	   "id": "oidc",
	   "type": "OpenIdConnectVersion1.0Service",
	   "serviceEndpoint": "https://openid.example.com/"
	}, 
	{
	   "id": "oidc-2",
	   "type": "OpenIdConnectVersion1.0Service",
	   "serviceEndpoint": ["https://openid.example.com/", "https://openid.example-2.com/"]
	}, 
	{
	   "id": "didcomm",
	   "type": "did-communication",
	   "serviceEndpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/",
	   "recipientKeys": ["%s"],
	   "routingKeys": ["%s"],
	   "priority": 0
	},
    {
      "id": "hub-1",
      "type": "IdentityHub",
      "serviceEndpoint": {
        "@context": "https://schema.identity.foundation/hub",
        "type": "UserHubEndpoint",
        "instances": ["did:example:456", "did:example:789"]
      }
    },
    {
      "id": "hub-2",
      "type": "IdentityHub",
      "serviceEndpoint": [{
        "uri": "https://example.com/path",
        "routingKeys": ["did:example:somemediator#somekey"]
	  }]
	},
    {
      "id": "hub-3",
      "type": "IdentityHub",
      "serviceEndpoint": [{
        "uri": "https://example.com/path",
        "accept": [
            "didcomm/v2",
            "didcomm/aip2;env=rfc587"
        ],
        "routingKeys": ["did:example:somemediator#somekey"]
	  },
      {
        "uri": "https://example-2.com/path",
        "routingKeys": ["did:example:somemediator2#somekey2"]
	  }]
	}
  ]
}`

const errorPatch = `[
{
"op": "move",
"path": "/test",
"value": "new value"
}
]`

var emptyJson = []byte("{}")

// DIDSideSteps
type DIDSideSteps struct {
	createRequest      *model.CreateRequest
	reuseKeys          bool
	recoveryKey        *ecdsa.PrivateKey
	recoveryNonce      string
	updateKey          *ecdsa.PrivateKey
	updateNonce        string
	resp               *restclient.HttpRespone
	bddContext         *BDDContext
	alias              string
	resolutionEndpoint string
	operationEndpoint  string
	interopOpType      string
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

	reqBytes, err := d.getCreateRequest(opaqueDoc, nil)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(d.operationEndpoint, reqBytes)
	if err == nil {
		var req model.CreateRequest
		e := json.Unmarshal(reqBytes, &req)
		if e != nil {
			return e
		}

		d.createRequest = &req
	}

	return err
}

func (d *DIDSideSteps) createDIDDocumentWithError(errType string) error {
	var err error

	logger.Infof("create did document with '%s' error", errType)

	var req *model.CreateRequest
	switch errType {
	case "request":
		// this error will be caught during create request validation
		p, err := getAddPublicKeysPatch("createKey")
		if err != nil {
			return err
		}

		req, err = d.getCreateRequestModel([]byte(""), []patch.Patch{p})
		if err != nil {
			return err
		}

		req.Delta = nil
	case "patch":
		// for create operation patch errors get caught during request time
		p, err := patch.NewJSONPatch(errorPatch)
		if err != nil {
			return err
		}

		req, err = d.getCreateRequestModel([]byte(""), []patch.Patch{p})
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("error type '%s' not supported", errType)
	}

	bytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	d.createRequest = req

	d.resp, err = restclient.SendRequest(d.operationEndpoint, bytes)
	return err
}

func (d *DIDSideSteps) updateDIDDocument(patches []patch.Patch) error {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	logger.Infof("update did document: %s", uniqueSuffix)

	req, err := d.getUpdateRequest(uniqueSuffix, patches)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(d.operationEndpoint, req)
	return err
}

func (d *DIDSideSteps) updateDIDDocumentWithError(errType string) error {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	logger.Infof("update did document [%s] with '%s' error", uniqueSuffix, errType)

	var req model.UpdateRequest
	switch errType {
	case "request":
		// this error will be caught during update request validation

		p, err := getAddPublicKeysPatch("keyID")
		if err != nil {
			return err
		}

		req, err = d.getUpdateRequestModel(uniqueSuffix, []patch.Patch{p})
		if err != nil {
			return err
		}

		req.Delta = nil
	case "resolution":
		// apply patch error will be caught during resolution (while applying operations)

		removeKey, err := getRemovePublicKeysPatch("createKey")
		if err != nil {
			return err
		}

		// patch that will cause an error
		jsonPatchWithErr, err := patch.NewJSONPatch(errorPatch)
		if err != nil {
			return err
		}

		req, err = d.getUpdateRequestModel(uniqueSuffix, []patch.Patch{removeKey, jsonPatchWithErr})
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("error type '%s' not supported", errType)
	}

	bytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(d.operationEndpoint, bytes)
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

	d.resp, err = restclient.SendRequest(d.operationEndpoint, req)
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

	req, err := d.getRecoverRequest(opaqueDoc, nil, uniqueSuffix)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(d.operationEndpoint, req)
	return err
}

func (d *DIDSideSteps) recoverDIDDocumentWithError(errType string) error {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	logger.Infof("recover did document [%s] with '%s' error", uniqueSuffix, errType)

	var req model.RecoverRequest
	switch errType {
	case "request":
		// this error will be caught during recover request validation
		opaqueDoc, err := d.getOpaqueDocument("recoveryKey")
		if err != nil {
			return err
		}

		req, err = d.getRecoverRequestModel(opaqueDoc, nil, uniqueSuffix)
		if err != nil {
			return err
		}

		// delta cannot be empty JSON
		req.Delta = nil

	case "resolution":
		// apply patch error will be caught during resolution
		p, err := patch.NewJSONPatch(errorPatch)
		if err != nil {
			return err
		}

		req, err = d.getRecoverRequestModel([]byte(""), []patch.Patch{p}, uniqueSuffix)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("error type '%s' not supported", errType)
	}

	bytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(d.operationEndpoint, bytes)
	return err
}

func (d *DIDSideSteps) updateDIDDocumentWithJSONPatch(path, value string) error {
	p, err := getJSONPatch(path, value)
	if err != nil {
		return err
	}

	return d.updateDIDDocument([]patch.Patch{p})
}

func (d *DIDSideSteps) addPublicKeyToDIDDocument(keyID string) error {
	p, err := getAddPublicKeysPatch(keyID)
	if err != nil {
		return err
	}

	return d.updateDIDDocument([]patch.Patch{p})
}

func (d *DIDSideSteps) removePublicKeyFromDIDDocument(keyID string) error {
	p, err := getRemovePublicKeysPatch(keyID)
	if err != nil {
		return err
	}

	return d.updateDIDDocument([]patch.Patch{p})
}

func (d *DIDSideSteps) addServiceEndpointToDIDDocument(keyID string) error {
	p, err := getAddServiceEndpointsPatch(keyID)
	if err != nil {
		return err
	}

	return d.updateDIDDocument([]patch.Patch{p})
}

func (d *DIDSideSteps) removeServiceEndpointsFromDIDDocument(keyID string) error {
	p, err := getRemoveServiceEndpointsPatch(keyID)
	if err != nil {
		return err
	}

	return d.updateDIDDocument([]patch.Patch{p})
}

func (d *DIDSideSteps) resolveDIDDocumentWithID(didID string) error {
	var err error
	logger.Infof("resolve did document %s with id", didID)

	d.resp, err = restclient.SendResolveRequest(d.resolutionEndpoint + "/" + didDocNamespace + docutil.NamespaceDelimiter + didID)
	return err
}

func (d *DIDSideSteps) checkErrorResp(errorMsg string) error {
	if !strings.Contains(d.resp.ErrorMsg, errorMsg) {
		return errors.Errorf("error resp %s doesn't contain %s", d.resp.ErrorMsg, errorMsg)
	}
	return nil
}

func (d *DIDSideSteps) discoverEndpoints() error {
	resp, err := restclient.SendResolveRequest("https://localhost:48326/.well-known/did")
	if err != nil {
		return err
	}

	var w restapi.WellKnownResponse
	if err := json.Unmarshal(resp.Payload, &w); err != nil {
		return err
	}

	resp, err = restclient.SendResolveRequest(
		fmt.Sprintf("https://localhost:48326/.well-known/webfinger?resource=%s",
			url.PathEscape(w.ResolutionEndpoint)))
	if err != nil {
		return err
	}

	var webFingerResponse restapi.WebFingerResponse
	if err := json.Unmarshal(resp.Payload, &webFingerResponse); err != nil {
		return err
	}

	d.resolutionEndpoint = strings.ReplaceAll(webFingerResponse.Links[0].Href, "domain1.com", "localhost:48326")

	resp, err = restclient.SendResolveRequest(
		fmt.Sprintf("https://localhost:48326/.well-known/webfinger?resource=%s",
			url.PathEscape(w.OperationEndpoint)))
	if err != nil {
		return err
	}

	if err := json.Unmarshal(resp.Payload, &webFingerResponse); err != nil {
		return err
	}

	d.operationEndpoint = strings.ReplaceAll(webFingerResponse.Links[0].Href, "domain1.com", "localhost:48326")

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

	if msg == "#did" || msg == "#aliasdid" || msg == "#emptydoc" {
		ns := didDocNamespace
		if msg == "#aliasdid" {
			ns = d.alias
		}

		did, err := d.getDIDWithNamespace(ns)
		if err != nil {
			return err
		}

		msg = strings.Replace(msg, "#did", did, -1)
		msg = strings.Replace(msg, "#aliasdid", did, -1)

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
			(len(didDoc.PublicKeys()) > 0 && !strings.Contains(didDoc.PublicKeys()[0].Controller(), didDoc.ID())) {
			return errors.New("response is not a valid did document")
		}

		if msg == "#emptydoc" {
			if len(didDoc) > 2 { // has id and context
				return errors.New("response is not an empty document")
			}

			logger.Info("response contains empty did document")

			return nil
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
	d.resp, err = restclient.SendResolveRequest(d.resolutionEndpoint + "/" + did)
	return err
}

func (d *DIDSideSteps) resolveDIDDocumentWithAlias(alias string) error {
	did, err := d.getDIDWithNamespace(alias)
	if err != nil {
		return err
	}

	d.alias = alias

	url := d.resolutionEndpoint + "/" + did

	d.resp, err = restclient.SendResolveRequest(url)
	return err
}

func (d *DIDSideSteps) resolveDIDDocumentWithInitialValue() error {
	did, err := d.getDID()
	if err != nil {
		return err
	}

	initialState, err := d.getInitialState()
	if err != nil {
		return err
	}

	req := d.resolutionEndpoint + "/" + did + initialStateSeparator + initialState

	d.resp, err = restclient.SendResolveRequest(req)
	return err
}

func (d *DIDSideSteps) resolveDIDDocumentWithInitialValueAndAlias(alias string) error {
	did, err := d.getDIDWithNamespace(alias)
	if err != nil {
		return err
	}

	d.alias = alias

	initialState, err := d.getInitialState()
	if err != nil {
		return err
	}

	req := d.resolutionEndpoint + "/" + did + initialStateSeparator + initialState

	d.resp, err = restclient.SendResolveRequest(req)
	return err
}

func (d *DIDSideSteps) getInitialState() (string, error) {
	createReq := &model.CreateRequest{
		Delta:      d.createRequest.Delta,
		SuffixData: d.createRequest.SuffixData,
	}

	bytes, err := canonicalizer.MarshalCanonical(createReq)
	if err != nil {
		return "", err
	}

	return encoder.EncodeToString(bytes), nil
}

func (d *DIDSideSteps) getCreateRequest(doc []byte, patches []patch.Patch) ([]byte, error) {
	recoveryNonce := d.generateNonce()

	recoveryKey, recoveryCommitment, err := getKeyAndCommitment(recoveryNonce)
	if err != nil {
		return nil, err
	}

	d.recoveryKey = recoveryKey
	d.recoveryNonce = recoveryNonce

	updateNonce := d.generateNonce()

	updateKey, updateCommitment, err := getKeyAndCommitment(updateNonce)
	if err != nil {
		return nil, err
	}

	d.updateKey = updateKey
	d.updateNonce = updateNonce

	return client.NewCreateRequest(&client.CreateRequestInfo{
		OpaqueDocument:     string(doc),
		Patches:            patches,
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      sha2_256,
	})
}

func (d *DIDSideSteps) getCreateRequestModel(doc []byte, patches []patch.Patch) (*model.CreateRequest, error) {
	reqBytes, err := d.getCreateRequest(doc, patches)
	if err != nil {
		return &model.CreateRequest{}, err
	}

	var req model.CreateRequest
	err = json.Unmarshal(reqBytes, &req)
	if err != nil {
		return &model.CreateRequest{}, err
	}

	return &req, nil
}

func (d *DIDSideSteps) getRecoverRequest(doc []byte, patches []patch.Patch, uniqueSuffix string) ([]byte, error) {
	recoveryKey, err := d.getRecoveryKey()
	if err != nil {
		return nil, err
	}

	updateKey, err := d.getUpdateKey()
	if err != nil {
		return nil, err
	}

	recoveryNonce := d.generateNonce()

	recoveryCommitment, err := getCommitment(recoveryKey, recoveryNonce)
	if err != nil {
		return nil, err
	}

	updateNonce := d.generateNonce()

	updateCommitment, err := getCommitment(updateKey, updateNonce)
	if err != nil {
		return nil, err
	}

	// recovery key and signer passed in are generated during previous operations
	recoveryPubKey, err := pubkey.GetPublicKeyJWK(&d.recoveryKey.PublicKey)
	if err != nil {
		return nil, err
	}

	recoveryPubKey.Nonce = d.recoveryNonce

	revealValue, err := commitment.GetRevealValue(recoveryPubKey, sha2_256)
	if err != nil {
		return nil, err
	}

	recoverRequest, err := client.NewRecoverRequest(&client.RecoverRequestInfo{
		DidSuffix:          uniqueSuffix,
		RevealValue:        revealValue,
		OpaqueDocument:     string(doc),
		Patches:            patches,
		RecoveryKey:        recoveryPubKey,
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      sha2_256,
		Signer:             ecsigner.New(d.recoveryKey, "ES256", ""), // sign with old signer
	})

	if err != nil {
		return nil, err
	}

	if d.reuseKeys {
		logger.Infof("setting recovery and update nonce")
		d.recoveryNonce = recoveryNonce
		d.updateNonce = updateNonce
	} else {
		logger.Infof("update recovery and update key for subsequent requests")
		d.recoveryKey = recoveryKey
		d.updateKey = updateKey
	}

	return recoverRequest, nil
}

func (d *DIDSideSteps) getUpdateKey() (*ecdsa.PrivateKey, error) {
	if d.reuseKeys {
		return d.updateKey, nil
	}

	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (d *DIDSideSteps) getRecoveryKey() (*ecdsa.PrivateKey, error) {
	if d.reuseKeys {
		return d.recoveryKey, nil
	}

	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (d *DIDSideSteps) generateNonce() string {
	if d.reuseKeys {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			panic(err) // this should never happen
		}

		return encoder.EncodeToString(nonceBytes)
	}

	return ""
}

func (d *DIDSideSteps) setReuseKeys(flag string) error {
	logger.Infof("setting reuse keys to '%s'", flag)

	var err error
	d.reuseKeys, err = strconv.ParseBool(flag)

	return err
}

func (d *DIDSideSteps) getRecoverRequestModel(doc []byte, patches []patch.Patch, uniqueSuffix string) (model.RecoverRequest, error) {
	reqBytes, err := d.getRecoverRequest(doc, patches, uniqueSuffix)
	if err != nil {
		return model.RecoverRequest{}, err
	}

	var req model.RecoverRequest
	err = json.Unmarshal(reqBytes, &req)
	if err != nil {
		return model.RecoverRequest{}, err
	}

	return req, nil
}

func (d *DIDSideSteps) getDID() (string, error) {
	return d.getDIDWithNamespace(didDocNamespace)
}

func (d *DIDSideSteps) getDIDWithNamespace(namespace string) (string, error) {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return "", err
	}

	didID := namespace + docutil.NamespaceDelimiter + uniqueSuffix
	return didID, nil
}

func (d *DIDSideSteps) getUniqueSuffix() (string, error) {
	return hashing.CalculateModelMultihash(d.createRequest.SuffixData, sha2_256)
}

func (d *DIDSideSteps) getDeactivateRequest(did string) ([]byte, error) {
	// recovery key and signer passed in are generated during previous operations
	recoveryPubKey, err := pubkey.GetPublicKeyJWK(&d.recoveryKey.PublicKey)
	if err != nil {
		return nil, err
	}

	recoveryPubKey.Nonce = d.recoveryNonce

	revealValue, err := commitment.GetRevealValue(recoveryPubKey, sha2_256)
	if err != nil {
		return nil, err
	}

	return client.NewDeactivateRequest(&client.DeactivateRequestInfo{
		DidSuffix:   did,
		RevealValue: revealValue,
		RecoveryKey: recoveryPubKey,
		Signer:      ecsigner.New(d.recoveryKey, "ES256", ""),
	})
}

func (d *DIDSideSteps) getUpdateRequest(did string, patches []patch.Patch) ([]byte, error) {
	updateKey, err := d.getUpdateKey()
	if err != nil {
		return nil, err
	}

	updateNonce := d.generateNonce()

	updateCommitment, err := getCommitment(updateKey, updateNonce)
	if err != nil {
		return nil, err
	}

	// update key and signer passed in are generated during previous operations
	updatePubKey, err := pubkey.GetPublicKeyJWK(&d.updateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	updatePubKey.Nonce = d.updateNonce

	revealValue, err := commitment.GetRevealValue(updatePubKey, sha2_256)
	if err != nil {
		return nil, err
	}

	req, err := client.NewUpdateRequest(&client.UpdateRequestInfo{
		DidSuffix:        did,
		RevealValue:      revealValue,
		UpdateCommitment: updateCommitment,
		UpdateKey:        updatePubKey,
		Patches:          patches,
		MultihashCode:    sha2_256,
		Signer:           ecsigner.New(d.updateKey, "ES256", ""),
	})

	if err != nil {
		return nil, err
	}

	if d.reuseKeys {
		logger.Infof("updating 'update' nonce")
		d.updateNonce = updateNonce
	} else {
		logger.Infof("updating 'update' key for subsequent requests")
		d.updateKey = updateKey
	}

	return req, nil
}

func (d *DIDSideSteps) getUpdateRequestModel(did string, patches []patch.Patch) (model.UpdateRequest, error) {
	reqBytes, err := d.getUpdateRequest(did, patches)
	if err != nil {
		return model.UpdateRequest{}, err
	}

	var req model.UpdateRequest
	err = json.Unmarshal(reqBytes, &req)
	if err != nil {
		return model.UpdateRequest{}, err
	}

	return req, nil
}

func getKeyAndCommitment(nonce string) (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	c, err := getCommitment(key, nonce)
	if err != nil {
		return nil, "", err
	}

	return key, c, nil
}

func getCommitment(key *ecdsa.PrivateKey, nonce string) (string, error) {
	pubKey, err := pubkey.GetPublicKeyJWK(&key.PublicKey)
	if err != nil {
		return "", err
	}

	pubKey.Nonce = nonce

	c, err := commitment.GetCommitment(pubKey, sha2_256)
	if err != nil {
		return "", err
	}

	return c, nil
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

func (d *DIDSideSteps) processRequest(opType, path string) error {
	var err error

	logger.Infof("processing operation request from '%s'", path)

	interopVectorsBytes, err := readRequest(path)
	if err != nil {
		return err
	}

	var interopVectors InteropVectors
	err = json.Unmarshal(interopVectorsBytes, &interopVectors)
	if err != nil {
		return err
	}

	var opRequest map[string]interface{}
	switch opType {
	case "create":
		opRequest = interopVectors.Create.OperationRequest
	case "recover":
		opRequest = interopVectors.Recover.OperationRequest
	case "update":
		opRequest = interopVectors.Update.OperationRequest
	case "deactivate":
		opRequest = interopVectors.Deactivate.OperationRequest
	default:
		return fmt.Errorf("operation type `%s` not supported for test vectors", opType)
	}

	d.interopOpType = opType

	reqBytes, err := canonicalizer.MarshalCanonical(opRequest)
	if err != nil {
		return err
	}

	if opType == "create" {
		var req model.CreateRequest
		err = json.Unmarshal(reqBytes, &req)
		if err != nil {
			return err
		}

		d.createRequest = &req
	}

	d.resp, err = restclient.SendRequest(d.operationEndpoint, reqBytes)
	return err
}

type InteropVectors struct {
	Create     CreateOperationVectors `json:"create,omitempty"`
	Update     OperationVectors       `json:"update,omitempty"`
	Recover    OperationVectors       `json:"recover,omitempty"`
	Deactivate OperationVectors       `json:"deactivate,omitempty"`
}

type OperationVectors struct {
	OperationRequest map[string]interface{} `json:"operationRequest,omitempty"`
}

type CreateOperationVectors struct {
	OperationVectors
	ShortFormDID string `json:"shortFormDid,omitempty"`
	LongFormDID  string `json:"longFormDid,omitempty"`
}

func (d *DIDSideSteps) resolveRequest(reqType, path string) error {
	var err error

	logger.Infof("processing resolve request from '%s'", path)

	interopVectorsBytes, err := readRequest(path)
	if err != nil {
		return err
	}

	var interopVectors InteropVectors
	err = json.Unmarshal(interopVectorsBytes, &interopVectors)
	if err != nil {
		return err
	}

	var req string
	switch reqType {
	case "long-form-did":
		req = interopVectors.Create.LongFormDID
	case "short-form-did":
		req = interopVectors.Create.ShortFormDID
	default:
		return fmt.Errorf("request type `%s` not supported for test vectors", reqType)
	}

	d.interopOpType = reqType

	d.resp, err = restclient.SendResolveRequest(d.resolutionEndpoint + "/" + req)

	return err
}

func (d *DIDSideSteps) processInteropResolveWithInitialValue() error {
	var err error

	d.resp, err = restclient.SendResolveRequest(d.resolutionEndpoint + "/" + interopResolveDidWithInitialState)
	return err
}

func (d *DIDSideSteps) validateResolutionResult(url string) error {
	if d.resp.ErrorMsg != "" {
		return errors.Errorf("error resp %s", d.resp.ErrorMsg)
	}

	body, err := readRequest(url)
	if err != nil {
		return err
	}

	var expected document.ResolutionResult

	err = json.Unmarshal(body, &expected)
	if err != nil {
		return err
	}

	prettyPrint(&expected)

	var result document.ResolutionResult
	err = json.Unmarshal(d.resp.Payload, &result)
	if err != nil {
		return err
	}

	prettyPrint(&result)

	err = validateMetadata(expected.DocumentMetadata, result.DocumentMetadata)
	if err != nil {
		return err
	}

	expectedDoc := document.DidDocumentFromJSONLDObject(expected.Document)
	doc := document.DidDocumentFromJSONLDObject(result.Document)

	err = validateDocument(expectedDoc, doc)
	if err != nil {
		return err
	}

	logger.Infof("successfully validated did document: %s", doc.ID())

	return nil
}

func (d *DIDSideSteps) matchResolutionResult(url string) error {
	if d.resp.ErrorMsg != "" {
		return errors.Errorf("error resp %s", d.resp.ErrorMsg)
	}

	return d.matchPartially(url, d.resp.Payload)
}

func (d *DIDSideSteps) matchErrorResolutionResult(url string) error {
	return d.matchResolutionResultWithPayload(url, []byte(d.resp.ErrorMsg))
}

func (d *DIDSideSteps) matchResolutionResultWithPayload(url string, payload []byte) error {
	body, err := readRequest(url)
	if err != nil {
		return err
	}

	var expected map[string]interface{}
	err = json.Unmarshal(body, &expected)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	err = json.Unmarshal(payload, &result)
	if err != nil {
		return err
	}

	expectedCanonical, err := canonicalizer.MarshalCanonical(expected)
	if err != nil {
		return err
	}

	resultCanonical, err := canonicalizer.MarshalCanonical(result)
	if err != nil {
		return err
	}

	if !bytes.Equal(expectedCanonical, resultCanonical) {
		return fmt.Errorf("resolution response[%s] doesn't match test vector[%s]", string(resultCanonical), string(expectedCanonical))
	}

	logger.Info("successfully matched canonical resulting document against test vector")

	return nil
}

func (d *DIDSideSteps) matchPartially(url string, payload []byte) error {
	body, err := readRequest(url)
	if err != nil {
		return err
	}

	opts := jsondiff.DefaultJSONOptions()

	_, str := jsondiff.Compare(body, payload, &opts)
	if str != expectedMismatches[d.interopOpType] {
		return fmt.Errorf(str)
	}

	logger.Info("successfully matched canonical resulting document against test vector")

	return nil
}

func validateDocument(expected, doc document.DIDDocument) error {
	if expected.ID() != doc.ID() {
		return fmt.Errorf("id mismatch: expected[%s], got[%s]", expected.ID(), doc.ID())
	}

	if len(expected.PublicKeys()) != len(doc.PublicKeys()) {
		return fmt.Errorf("public keys mismatch: expected[%d], got[%d]", len(expected.PublicKeys()), len(doc.PublicKeys()))
	}

	for i := 0; i < len(expected.PublicKeys()); i++ {
		err := validateKey(expected.PublicKeys()[i], doc.PublicKeys()[i])
		if err != nil {
			return err
		}
	}

	if len(expected.Services()) != len(doc.Services()) {
		return fmt.Errorf("services mismatch: expected[%d], got[%d]", len(expected.Services()), len(doc.Services()))
	}

	for i := 0; i < len(expected.Services()); i++ {
		err := validateService(expected.Services()[i], doc.Services()[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func validateKey(expected, key document.PublicKey) error {
	if !strings.Contains(key.ID(), expected.ID()) {
		return fmt.Errorf("public key id mismatch: expected[%s], got[%s]", expected.ID(), key.ID())
	}

	if key.Type() != expected.Type() {
		return fmt.Errorf("public key type mismatch: expected[%s], got[%s]", expected.Type(), key.Type())
	}

	if expected.PublicKeyJwk().Crv() != key.PublicKeyJwk().Crv() {
		return fmt.Errorf("crv mismatch: expected[%s], got[%s]", expected.PublicKeyJwk().Crv(), key.PublicKeyJwk().Crv())
	}

	if expected.PublicKeyJwk().Kty() != key.PublicKeyJwk().Kty() {
		return fmt.Errorf("kty mismatch: expected[%s], got[%s]", expected.PublicKeyJwk().Kty(), key.PublicKeyJwk().Kty())
	}

	if expected.PublicKeyJwk().X() != key.PublicKeyJwk().X() {
		return fmt.Errorf("x mismatch: expected[%s], got[%s]", expected.PublicKeyJwk().X(), key.PublicKeyJwk().X())
	}

	if expected.PublicKeyJwk().Y() != key.PublicKeyJwk().Y() {
		return fmt.Errorf("y mismatch: expected[%s], got[%s]", expected.PublicKeyJwk().Y(), key.PublicKeyJwk().Y())
	}

	return nil
}

func validateService(expected, service document.Service) error {
	if !strings.Contains(service.ID(), expected.ID()) {
		return fmt.Errorf("service id mismatch: expected[%s], got[%s]", expected.ID(), service.ID())
	}

	if expected.Type() != service.Type() {
		return fmt.Errorf("service type mismatch: expected[%s], got[%s]", expected.Type(), service.Type())
	}

	if expected.ServiceEndpoint() != service.ServiceEndpoint() {
		return fmt.Errorf("service endpoint mismatch: expected[%s], got[%s]", expected.Type(), service.Type())
	}

	return nil
}

func validateMetadata(expected, metadata document.Metadata) error {
	methodMetadata, err := getMethodMetadata(metadata)
	if err != nil {
		return fmt.Errorf("result metadata: %s", err.Error())
	}

	expectedMethodMetadata, err := getMethodMetadata(expected)
	if err != nil {
		return fmt.Errorf("expected metadata: %s", err.Error())
	}

	if expectedMethodMetadata[document.RecoveryCommitmentProperty] != methodMetadata[document.RecoveryCommitmentProperty] {
		return fmt.Errorf("recovery commitment mismatch: expected[%s], got[%s]", expected[document.RecoveryCommitmentProperty], metadata[document.RecoveryCommitmentProperty])
	}

	if expectedMethodMetadata[document.UpdateCommitmentProperty] != methodMetadata[document.UpdateCommitmentProperty] {
		return fmt.Errorf("update commitment mismatch: expected[%s], got[%s]", expected[document.UpdateCommitmentProperty], metadata[document.UpdateCommitmentProperty])
	}

	// Validate is used for validating return value of create request so published will not match against interop resolution result

	return nil
}

func getMethodMetadata(docMetadata document.Metadata) (document.Metadata, error) {
	methodMetadataEntry, ok := docMetadata[document.MethodProperty]
	if !ok {
		return nil, errors.New("missing method metadata")
	}

	methodMetadata, ok := methodMetadataEntry.(map[string]interface{})
	if !ok {
		return nil, errors.New("wrong type for method metadata")
	}

	return methodMetadata, nil
}

func readRequest(url string) ([]byte, error) {
	client := &http.Client{}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}
	if status := resp.StatusCode; status != http.StatusOK {
		return nil, errors.New(string(body))
	}
	return body, nil
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

	fmt.Println(string(b))

	return nil
}

// RegisterSteps registers did sidetree steps
func (d *DIDSideSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^client discover endpoints$`, d.discoverEndpoints)
	s.Step(`^check error response contains "([^"]*)"$`, d.checkErrorResp)
	s.Step(`^client sends request to create DID document$`, d.createDIDDocument)
	s.Step(`^client sends request to create DID document with "([^"]*)" error$`, d.createDIDDocumentWithError)
	s.Step(`^check success response contains "([^"]*)"$`, d.checkSuccessRespContains)
	s.Step(`^check success response does NOT contain "([^"]*)"$`, d.checkSuccessRespDoesntContain)
	s.Step(`^client sends request to resolve DID document$`, d.resolveDIDDocument)
	s.Step(`^client sends request to resolve DID document with alias "([^"]*)"$`, d.resolveDIDDocumentWithAlias)
	s.Step(`^client sends request to update DID document path "([^"]*)" with value "([^"]*)"$`, d.updateDIDDocumentWithJSONPatch)
	s.Step(`^client sends request to add public key with ID "([^"]*)" to DID document$`, d.addPublicKeyToDIDDocument)
	s.Step(`^client sends request to remove public key with ID "([^"]*)" from DID document$`, d.removePublicKeyFromDIDDocument)
	s.Step(`^client sends request to add service endpoint with ID "([^"]*)" to DID document$`, d.addServiceEndpointToDIDDocument)
	s.Step(`^client sends request to remove service endpoint with ID "([^"]*)" from DID document$`, d.removeServiceEndpointsFromDIDDocument)
	s.Step(`^client sends request to update DID document with "([^"]*)" error$`, d.updateDIDDocumentWithError)
	s.Step(`^client sends request to deactivate DID document$`, d.deactivateDIDDocument)
	s.Step(`^client sends request to recover DID document$`, d.recoverDIDDocument)
	s.Step(`^client sends request to recover DID document with "([^"]*)" error$`, d.recoverDIDDocumentWithError)
	s.Step(`^client sends request to resolve DID document with initial state$`, d.resolveDIDDocumentWithInitialValue)
	s.Step(`^client sends request to resolve DID document with initial state and with alias "([^"]*)"$`, d.resolveDIDDocumentWithInitialValueAndAlias)
	s.Step(`^client sends "([^"]*)" operation request from "([^"]*)"$`, d.processRequest)
	s.Step(`^client sends "([^"]*)" resolve request from "([^"]*)"$`, d.resolveRequest)
	s.Step(`^success response is validated against resolution result "([^"]*)"$`, d.validateResolutionResult)
	s.Step(`^success response matches resolution result "([^"]*)"$`, d.matchResolutionResult)
	s.Step(`^error response matches resolution result "([^"]*)"$`, d.matchErrorResolutionResult)
	s.Step(`^client sends interop resolve with initial value request$`, d.processInteropResolveWithInitialValue)
	s.Step(`^client sets reuse keys for did operations to "([^"]*)"$`, d.setReuseKeys)
	s.Step(`^we wait (\d+) seconds$`, wait)
}

const interopResolveDidWithInitialState = `did:sidetree:EiBFsUlzmZ3zJtSFeQKwJNtngjmB51ehMWWDuptf9b4Bag?-sidetree-initial-state=eyJkZWx0YV9oYXNoIjoiRWlCWE00b3RMdVAyZkc0WkE3NS1hbnJrV1ZYMDYzN3hadE1KU29Lb3AtdHJkdyIsInJlY292ZXJ5X2NvbW1pdG1lbnQiOiJFaUM4RzRJZGJEN0Q0Q281N0dqTE5LaG1ERWFicnprTzF3c0tFOU1RZVV2T2d3In0.eyJ1cGRhdGVfY29tbWl0bWVudCI6IkVpQ0lQY1hCempqUWFKVUljUjUyZXVJMHJJWHpoTlpfTWxqc0tLOXp4WFR5cVEiLCJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljX2tleXMiOlt7ImlkIjoic2lnbmluZ0tleSIsInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkiLCJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoieTlrenJWQnFYeDI0c1ZNRVFRazRDZS0wYnFaMWk1VHd4bGxXQ2t6QTd3VSIsInkiOiJjMkpIeFFxVVV0eVdJTEFJaWNtcEJHQzQ3UGdtSlQ0NjV0UG9jRzJxMThrIn0sInB1cnBvc2UiOlsiYXV0aCIsImdlbmVyYWwiXX1dLCJzZXJ2aWNlX2VuZHBvaW50cyI6W3siaWQiOiJzZXJ2aWNlRW5kcG9pbnRJZDEyMyIsInR5cGUiOiJzb21lVHlwZSIsImVuZHBvaW50IjoiaHR0cHM6Ly93d3cudXJsLmNvbSJ9XX19XX0`

var expectedMismatches = map[string]string{
	"create":        expectedMismatchAfterCreate,
	"update":        expectedMismatchAfterUpdate,
	"recover":       expectedMismatchAfterRecover,
	"deactivate":    expectedMismatchAfterDeactivate,
	"long-form-did": expectedMismatchAfterLongFormDID,
}

var expectedMismatchAfterCreate = `{
    "@context": "https://w3id.org/did-resolution/v1",
    "didDocument": {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            {
                "@base": "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"
            },
            "prop-added":{"https://w3id.org/security/suites/secp256k1-2019/v1"}
        ],
        "authentication": [
            "#publicKeyModel1Id"
        ],
        "id": "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
        "keyAgreement": [
            "#publicKeyModel1Id"
        ],
        "service": [
            {
                "id": "#service1Id",
                "serviceEndpoint": "http://www.service1.com",
                "type": "service1Type"
            }
        ],
        "verificationMethod": [
            {
                "controller": {"changed":["did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg", ""]},
                "id": "#publicKeyModel1Id",
                "publicKeyJwk": {
                    "crv": "secp256k1",
                    "kty": "EC",
                    "x": "tXSKB_rubXS7sCjXqupVJEzTcW3MsjmEvq1YpXn96Zg",
                    "y": "dOicXqbjFxoGJ-K0-GJ1kHYJqic_D_OMuUwkQ7Ol6nk"
                },
                "type": "EcdsaSecp256k1VerificationKey2019"
            }
        ]
    },
    "didDocumentMetadata": {
        "canonicalId": "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
        "prop-added":{"created": "1970-01-01T00:00:00Z"},
        "prop-added":{"equivalentId": [}
            "prop-added":{"did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"}
        "prop-added":{]},
        "method": {
            "published": true,
            "recoveryCommitment": "EiBfOZdMtU6OBw8Pk879QtZ-2J-9FbbjSZyoaA_bqD4zhA",
            "updateCommitment": "EiDKIkwqO69IPG3pOlHkdb86nYt0aNxSHZu2r-bhEznjdA"
        }
    }
}`

var expectedMismatchAfterUpdate = `{
    "@context": "https://w3id.org/did-resolution/v1",
    "didDocument": {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            {
                "@base": "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"
            },
            "prop-added":{"https://w3id.org/security/suites/secp256k1-2019/v1"}
        ],
        "assertionMethod": [
            "#additional-key"
        ],
        "authentication": [
            "#publicKeyModel1Id",
            "#additional-key"
        ],
        "capabilityDelegation": [
            "#additional-key"
        ],
        "capabilityInvocation": [
            "#additional-key"
        ],
        "id": "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
        "keyAgreement": [
            "#publicKeyModel1Id",
            "#additional-key"
        ],
        "service": [
            {
                "id": "#service1Id",
                "serviceEndpoint": "http://www.service1.com",
                "type": "service1Type"
            }
        ],
        "verificationMethod": [
            {
                "controller": {"changed":["did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg", ""]},
                "id": "#publicKeyModel1Id",
                "publicKeyJwk": {
                    "crv": "secp256k1",
                    "kty": "EC",
                    "x": "tXSKB_rubXS7sCjXqupVJEzTcW3MsjmEvq1YpXn96Zg",
                    "y": "dOicXqbjFxoGJ-K0-GJ1kHYJqic_D_OMuUwkQ7Ol6nk"
                },
                "type": "EcdsaSecp256k1VerificationKey2019"
            },
            {
                "controller": {"changed":["did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg", ""]},
                "id": "#additional-key",
                "publicKeyJwk": {
                    "crv": "secp256k1",
                    "kty": "EC",
                    "x": "aN75CTjy3VCgGAJDNJHbcb55hO8CobEKzgCNrUeOwAY",
                    "y": "K9FhCEpa_jG09pB6qriXrgSvKzXm6xtxBvZzIoXXWm4"
                },
                "type": "EcdsaSecp256k1VerificationKey2019"
            }
        ]
    },
    "didDocumentMetadata": {
        "canonicalId": "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
        "prop-added":{"created": "1970-01-01T00:00:00Z"},
        "prop-added":{"equivalentId": [}
            "prop-added":{"did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"}
        "prop-added":{]},
        "method": {
            "published": true,
            "recoveryCommitment": "EiBfOZdMtU6OBw8Pk879QtZ-2J-9FbbjSZyoaA_bqD4zhA",
            "updateCommitment": "EiDOrcmPtfMHuwIWN6YoihdeIPxOKDHy3D6sdMXu_7CN0w"
        }
    }
}`

var expectedMismatchAfterRecover = `{
    "@context": "https://w3id.org/did-resolution/v1",
    "didDocument": {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            {
                "@base": "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"
            },
            "prop-added":{"https://w3id.org/security/suites/secp256k1-2019/v1"}
        ],
        "assertionMethod": [
            "#newKey"
        ],
        "authentication": [
            "#newKey"
        ],
        "capabilityDelegation": [
            "#newKey"
        ],
        "capabilityInvocation": [
            "#newKey"
        ],
        "id": "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
        "keyAgreement": [
            "#newKey"
        ],
        "service": [
            {
                "id": "#serviceId123",
                "serviceEndpoint": "https://www.url.com",
                "type": "someType"
            }
        ],
        "verificationMethod": [
            {
                "controller": {"changed":["did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg", ""]},
                "id": "#newKey",
                "publicKeyJwk": {
                    "crv": "secp256k1",
                    "kty": "EC",
                    "x": "JUWp0pAMGevNLhqq_Qmd48izuLYfO5XWpjSmy5btkjc",
                    "y": "QYaSu1NHYnxR4qfk-RkXb4NQnQf1X3XQCpDYuibvlNc"
                },
                "type": "EcdsaSecp256k1VerificationKey2019"
            }
        ]
    },
    "didDocumentMetadata": {
        "canonicalId": "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
        "prop-added":{"created": "1970-01-01T00:00:00Z"},
        "prop-added":{"equivalentId": [}
            "prop-added":{"did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"}
        "prop-added":{]},
        "method": {
            "published": true,
            "recoveryCommitment": "EiCsA7SGLNeda5InloqnokUcJFz6vKT4HS5dcKrmnlJhpA",
            "updateCommitment": "EiD6_csybTfxELBoMgkE9O2BTCmhScG_RW_qaZQkIkJ_aQ"
        }
    }
}`

var expectedMismatchAfterDeactivate = `{
    "@context": "https://w3id.org/did-resolution/v1",
    "didDocument": {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            {
                "@base": "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"
            }
        ],
        "id": "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"
    },
    "didDocumentMetadata": {
        "canonicalId": "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg",
        "prop-added":{"created": "1970-01-01T00:00:00Z"},
        "deactivated": true,
        "prop-added":{"equivalentId": [}
            "prop-added":{"did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"}
        "prop-added":{]},
        "method": {
            "published": true
        }
    }
}`

var expectedMismatchAfterLongFormDID = `{
    "@context": "https://w3id.org/did-resolution/v1",
    "didDocument": {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            {
                "@base": "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ"
            },
            "prop-added":{"https://w3id.org/security/suites/secp256k1-2019/v1"}
        ],
        "authentication": [
            "#publicKeyModel1Id"
        ],
        "id": "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ",
        "keyAgreement": [
            "#publicKeyModel1Id"
        ],
        "service": [
            {
                "id": "#service1Id",
                "serviceEndpoint": "http://www.service1.com",
                "type": "service1Type"
            }
        ],
        "verificationMethod": [
            {
                "controller": {"changed":["did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ", ""]},
                "id": "#publicKeyModel1Id",
                "publicKeyJwk": {
                    "crv": "secp256k1",
                    "kty": "EC",
                    "x": "tXSKB_rubXS7sCjXqupVJEzTcW3MsjmEvq1YpXn96Zg",
                    "y": "dOicXqbjFxoGJ-K0-GJ1kHYJqic_D_OMuUwkQ7Ol6nk"
                },
                "type": "EcdsaSecp256k1VerificationKey2019"
            }
        ]
    },
    "didDocumentMetadata": {
        "equivalentId": [
            "did:sidetree:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"
        ],
        "method": {
            "published": false,
            "recoveryCommitment": "EiBfOZdMtU6OBw8Pk879QtZ-2J-9FbbjSZyoaA_bqD4zhA",
            "updateCommitment": "EiDKIkwqO69IPG3pOlHkdb86nYt0aNxSHZu2r-bhEznjdA"
        }
    }
}`
