#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did-sidetree
Feature:

  @create_valid_did_doc
  Scenario: create valid did doc
    When client sends request to create DID document
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

  @create_deactivate_did_doc
  Scenario: deactivate valid did doc
    When client sends request to create DID document
    Then check success response contains "#didDocumentHash"
    Then we wait 1 seconds
    When client sends request to resolve DID document
    Then check success response contains "#didDocumentHash"
    When client sends request to deactivate DID document
    Then we wait 1 seconds
    When client sends request to resolve DID document
    Then check error response contains "document is no longer available"

  @create_recover_did_doc
  Scenario: recover did doc
    When client sends request to create DID document
    Then check success response contains "#didDocumentHash"
    Then we wait 1 seconds
    When client sends request to resolve DID document
    Then check success response contains "#didDocumentHash"
    When client sends request to recover DID document
    Then we wait 1 seconds
    When client sends request to resolve DID document
    Then check success response contains "recoveryKey"

    @create_add_remove_public_key
    Scenario: add and remove public keys
      When client sends request to create DID document
      Then check success response contains "#didDocumentHash"
      Then we wait 1 seconds
      When client sends request to add public key with ID "newKey" to DID document
      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "newKey"
      When client sends request to remove public key with ID "newKey" from DID document
      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response does NOT contain "newKey"

    @create_add_remove_services
    Scenario: add and remove service endpoints
      When client sends request to create DID document
      Then check success response contains "#didDocumentHash"
      Then we wait 1 seconds
      When client sends request to add service endpoint with ID "newService" to DID document
      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "newService"
      When client sends request to remove service endpoint with ID "newService" from DID document
      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response does NOT contain "newService"