Sidetree Protocol Go Implementation
===================================

Sidetree node exposes a set of REST API that enables the creation of new DIDs and their initial state, subsequent DID Document updates and DID Document
resolutions. API uses design first approach to generate a server stub for API using `go swagger <https://github.com/go-swagger/go-swagger>`_.
The API structure is defined in swagger.yaml.

Sidetree REST API
-----------------

**DID and DID Document Creation**

Request Path ::

 Post /sidetree/0.0.1/operations


**DID Document resolution**

Request Path ::

 GET  /sidetree/0.0.1/identifiers/{DidOrDidDocument}

**Updating a DID Document**

Request Path ::

 Post /sidetree/0.0.1/operations

**DID Deletion**

Request Path ::

 Post /sidetree/0.0.1/operations

**DID Resolution**

The Request handler resolve operation uses Operation processor resolves method by passing *input parameter DIDUniqueSuffix* to its DID document.
Operation processor resolve iterate over all operations and apply each operation in chronological order to build a complete DID Document.

.. note:: To follow the sample Request and Response for each of the above operation. Refer to `Sidetree Protocol <https://github.com/decentralized-identity/sidetree/blob/master/docs/protocol.md>`_.
