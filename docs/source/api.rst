Sidetree Protocol Go Implementation
===================================

Sidetree node exposes a set of REST API that enables the creation of new DIDs and their initial state, subsequent DID Document updates and DID Document
resolutions. API uses design first approach to generate a server stub for API using `go swagger <https://github.com/go-swagger/go-swagger>`_.
The API structure is defined in swagger.yaml.

**Sidetree Request Handler**

Sidetree-node Request handler implements sidetree node context. Request Handler act as the entry point for client request which perform common validation
for any operation request. Each request is validated against the following ::

 1. Length of request is greater than MaxOperationByteSize of the request protocol
 2. For operation create, request cannot have didID before its being created
 3. For operation create, validate generic original document schema
 4. For non create operation validate if didUniqueSuffix exists in operation store

For operation type Create, Sidetree DID document is created and returns the original document with DID added to it.
For any other operation, handler doesnt do anything. Returns 200 Status on successful response.

Sidetree Node Context contains the following:
 - protocol information client
 - content addressable storage client (CAS Client)
 - blockchain client
 - operations store client

**Operation Processor**

OperationProcessor is an interface which resolves the DID document based on the DID

**BatchWriter**

BatchWriter is an interface to add an operation to the Batch

Sidetree REST API
-----------------

**DID and DID Document Creation**

Request Path ::

 Post /document


**DID Document resolution**

Request Path ::

 GET  /document/{DidOrDidDocument}

**Updating a DID Document**

Request Path ::

 Post /document

**DID Deletion**

Request Path ::

  Post /document

**DID Resolution**

The Request handler resolve operation uses Operation processor resolves method by passing *input parameter DIDUniqueSuffix* to its DID document.
Operation processor resolve iterate over all operations and apply each operation in chronological order to build a complete DID Document.

.. note:: To follow the sample Request and Response for each of the above operation. Refer to `Sidetree Protocol <https://github.com/decentralized-identity/sidetree/blob/master/docs/protocol.md>`_.
