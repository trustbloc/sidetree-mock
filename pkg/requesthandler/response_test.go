/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package requesthandler

import (
	"io"
	"net/http/httptest"
	"testing"

	"github.com/pkg/errors"
	"github.com/trustbloc/sidetree-node/models"
)

func TestWriteBodyError(t *testing.T) {

	defer handlePanic(t)

	err := NotFoundError{&models.Error{}}
	writeBody(httptest.NewRecorder(), &mockProducer{}, err.error)
}

type mockProducer struct {
}

// Produce writes to the http response
func (m *mockProducer) Produce(io.Writer, interface{}) error {
	return errors.New("producer error")
}

// handlePanic handles a panic
func handlePanic(t *testing.T) {
	if r := recover(); r != nil {
		// expected to panic - success
		return
	}

	// no panic - fail here
	t.Fail()
}
