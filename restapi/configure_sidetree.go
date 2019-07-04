// This file is safe to edit. Once it exists it will not be overwritten

package restapi

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-openapi/runtime/middleware"

	"github.com/go-openapi/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/dochandler"
	"github.com/trustbloc/sidetree-core-go/pkg/dochandler/didvalidator"
	"github.com/trustbloc/sidetree-core-go/pkg/processor"
	"github.com/trustbloc/sidetree-node/pkg/observer"

	"github.com/go-openapi/runtime"
	"github.com/trustbloc/sidetree-node/pkg/context"
	"github.com/trustbloc/sidetree-node/pkg/requesthandler"
	"github.com/trustbloc/sidetree-node/restapi/operations"
)

//go:generate swagger generate server --target ../../sidetree-node --name Sidetree --spec ../api/swagger.yaml

var logger = logrus.New()
var config = viper.New()

const didDocNamespace = "did:sidetree:"

func configureFlags(api *operations.SidetreeAPI) { //nolint:unparam

	// Set command line options from environment variables if available
	args := []string{
		"scheme",
		"cleanup-timeout",
		"graceful-timeout",
		"max-header-size",
		"socket-path",
		"host",
		"port",
		"listen-limit",
		"keep-alive",
		"read-timeout",
		"write-timeout",
		"tls-host",
		"tls-port",
		"tls-certificate",
		"tls-key",
		"tls-ca",
		"tls-listen-limit",
		"tls-keep-alive",
		"tls-read-timeout",
		"tls-write-timeout",
	}
	for _, a := range args {
		if envVar := os.Getenv(fmt.Sprintf("SIDETREE_NODE_%s", strings.Replace(strings.ToUpper(a), "-", "_", -1))); envVar != "" {
			os.Args = append(os.Args, fmt.Sprintf("--%s=%s", a, envVar))
		}
	}
}

func configureAPI(api *operations.SidetreeAPI) http.Handler {
	// configure the api here
	api.ServeError = errors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf

	api.JSONConsumer = runtime.JSONConsumer()
	api.ApplicationJoseProducer = runtime.JSONProducer()
	api.JSONProducer = runtime.JSONProducer()

	config.SetEnvPrefix("SIDETREE_NODE")
	config.AutomaticEnv()
	config.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	logger.Info("starting sidetree node...")

	ctx, err := context.New(config)
	if err != nil {
		logger.Errorf("Failed to create new context: %s", err.Error())
		http.Error(nil, err.Error(), http.StatusInternalServerError)
	}

	// create new batch writer
	batchWriter, err := batch.New(ctx)
	if err != nil {
		logger.Errorf("Failed to create batch writer: %s", err.Error())
		http.Error(nil, err.Error(), http.StatusInternalServerError)
	}

	// start routine for creating batches
	batchWriter.Start()

	// start observer
	observer.Start(ctx.Blockchain(), ctx.CAS(), ctx.OperationStore())

	// did document handler with did document validator for didDocNamespace
	didDocHandler := dochandler.New(
		didDocNamespace,
		ctx.Protocol(),
		didvalidator.New(ctx.OperationStore()),
		batchWriter,
		processor.New(ctx.OperationStore()),
	)

	didResolutionHandler := requesthandler.NewResolutionHandler(didDocNamespace, ctx.Protocol(), didDocHandler)
	didOperationHandler := requesthandler.NewOperationHandler(didDocNamespace, ctx.Protocol(), didDocHandler)

	api.PostDocumentHandler = operations.PostDocumentHandlerFunc(
		func(params operations.PostDocumentParams) middleware.Responder {
			return didOperationHandler.HandleOperationRequest(params.Request)
		},
	)
	api.GetDocumentDidOrDidDocumentHandler = operations.GetDocumentDidOrDidDocumentHandlerFunc(
		func(params operations.GetDocumentDidOrDidDocumentParams) middleware.Responder {
			return didResolutionHandler.HandleResolveRequest(params.DidOrDidDocument)
		},
	)

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix"
func configureServer(s *http.Server, scheme, addr string) {
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	return handler
}
