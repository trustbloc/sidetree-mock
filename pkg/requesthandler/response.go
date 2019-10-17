/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package requesthandler

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// Response implements middleware.Responder
type Response struct {
	Body   interface{}
	Status uint
}

// WriteResponse writes the response to the client
func (o *Response) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {
	rw.WriteHeader(http.StatusOK)
	writeBody(rw, producer, o.Body)
}

//BadRequestError holds the error which occurred during the operation
type BadRequestError struct {
	error string
}

// WriteResponse writes the response to the client
func (o *BadRequestError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {
	rw.WriteHeader(http.StatusBadRequest)
	writeBody(rw, producer, o.error)
}

//InternalServerError holds the internal server error which occurred during the operation
type InternalServerError struct {
	error string
}

// WriteResponse writes the response to the client
func (o *InternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {
	rw.WriteHeader(http.StatusInternalServerError)
	writeBody(rw, producer, o.error)
}

//NotFoundError holds the error when the DID document is not found
type NotFoundError struct {
	error string
}

// WriteResponse writes the response to the client
func (o *NotFoundError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {
	rw.WriteHeader(http.StatusNotFound)
	writeBody(rw, producer, o.error)
}

func writeBody(rw http.ResponseWriter, producer runtime.Producer, obj interface{}) {
	if obj != nil {
		if err := producer.Produce(rw, obj); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
