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
    When client sends request to create DID document "fixtures/config/didDocument.json" with ID "did:sidetree:123"
    Then check error response contains "document must NOT have the id property"
    When client sends request to resolve DID document "fixtures/config/didDocument.json" with ID "did:sidetree:abc"
    Then check error response contains "document must NOT have the id property"

  @create_valid_did_doc
  Scenario: create valid did doc
    When client sends request to create DID document "fixtures/config/didDocument.json"
    Then check success response contains "#didDocumentHash"
    # retrieve document with initial value before it becomes available on the ledger
    When client sends request to resolve DID document with initial value
    Then check success response contains "#didDocumentHash"
    # we wait until observer poll sidetree txn from ledger
    Then we wait 1 seconds
    When client sends request to resolve DID document
    Then check success response contains "#didDocumentHash"
    # retrieve document with initial value after it becomes available on the ledger
    When client sends request to resolve DID document with initial value
    Then check success response contains "#didDocumentHash"

  @create_revoke_did_doc
  Scenario: revoke valid did doc
    When client sends request to create DID document "fixtures/config/didDocument.json"
    Then check success response contains "#didDocumentHash"
    Then we wait 1 seconds
    When client sends request to resolve DID document
    Then check success response contains "#didDocumentHash"
    When client sends request to revoke DID document
    Then we wait 1 seconds
    When client sends request to resolve DID document
    Then check error response contains "document is no longer available"

    @create_update_did_doc
    Scenario: revoke valid did doc
      When client sends request to create DID document "fixtures/config/didDocument.json"
      Then check success response contains "#didDocumentHash"
      Then we wait 1 seconds
      When client sends request to update DID document path "/publicKey/0/type" with value "updatedValue"
      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "updatedValue"
