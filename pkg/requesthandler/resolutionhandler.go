/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package requesthandler

import (
	"net/http"
	"strings"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/swag"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-node/models"
)

//ResolutionHandler delegates resolution to document handler
type ResolutionHandler struct {
	namespace   string
	protocol    protocol.Client
	docResolver DocumentResolver
}

// DocumentResolver is an interface which allows for resolving documents based on id or document
type DocumentResolver interface {
	ResolveDocument(idOrDocument string) (document.Document, error)
}

// NewResolutionHandler creates new resolution handler
func NewResolutionHandler(namespace string, protocol protocol.Client, handler DocumentResolver) *ResolutionHandler {
	return &ResolutionHandler{
		namespace:   namespace,
		protocol:    protocol,
		docResolver: handler,
	}
}

// HandleResolveRequest returns the responder for the operation GetDocumentDidOrDidDocumentParams
func (r *ResolutionHandler) HandleResolveRequest(idOrDocument string) middleware.Responder {

	if !strings.HasPrefix(idOrDocument, r.namespace) {
		return &BadRequestError{&models.Error{Message: swag.String("must start with supported namespace")}}
	}

	didDoc, err := r.docResolver.ResolveDocument(idOrDocument)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return &NotFoundError{&models.Error{Message: swag.String("document not found")}}
		}

		return &InternalServerError{&models.Error{Message: swag.String(err.Error())}}
	}

	return &Response{Body: &models.Response{Body: didDoc}, Status: http.StatusOK}
}
