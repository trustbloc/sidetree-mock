#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did-sidetree
Feature:

  @create_invalid_did_doc
  Scenario: create invalid doc
    When client sends request to create DID document "fixtures/config/didDocument.json" as "JSON" with DID id "123"
    Then check error response contains "document must NOT have the id property"
    When client sends request to create DID document "fixtures/config/didDocument.json" as "queryParameter" with DID id "123"
    Then check error response contains "document must NOT have the id property"


  @create_valid_did_doc
  Scenario: create valid did doc
    When client sends request to create DID document "fixtures/config/didDocument.json" as "JSON"
    Then check success response contains "#didDocumentHash"
    When client sends request to resolve DID document
    Then check success response contains "#didDocumentHash"
    When client sends request to create DID document "fixtures/config/didDocument.json" as "queryParameter"
    Then check success response contains "#didDocumentHash"
