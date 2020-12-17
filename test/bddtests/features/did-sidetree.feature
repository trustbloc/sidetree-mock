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
    Then check success response contains "#did"
    # retrieve document with initial value before it becomes available on the ledger
    When client sends request to resolve DID document with initial state
    Then check success response contains "#did"
    # retrieve document with initial value and alias before it becomes available on the ledger
    When client sends request to resolve DID document with initial state and with alias "did:domain.com"
    Then check success response contains "#aliasdid"
    # we wait until observer poll sidetree txn from ledger
    Then we wait 1 seconds
    When client sends request to resolve DID document
    Then check success response contains "#did"
    When client sends request to resolve DID document with alias "did:domain.com"
    Then check success response contains "#did"
    Then check success response contains "#aliasdid"
    When client sends request to resolve DID document with alias "did:notconfigured.com"
    Then check error response contains "did must start with configured namespace[did:sidetree] or aliases[did:alias.com did:domain.com]"

    # retrieve document with initial value after it becomes available on the ledger
    When client sends request to resolve DID document with initial state
    Then check success response contains "#did"

    # retrieve document with initial value and alias after it becomes available on the ledger
    When client sends request to resolve DID document with initial state and with alias "did:domain.com"
    Then check success response contains "#did"
    Then check success response contains "#aliasdid"

    When client sends request to create DID document with "patch" error
    Then check error response contains "applying delta resulted in an empty document (most likely due to an invalid patch)"

    When client sends request to create DID document with "request" error
    Then check error response contains "missing delta"

  @create_deactivate_did_doc
  Scenario: deactivate valid did doc
    When client sends request to create DID document
    Then check success response contains "#did"
    Then we wait 1 seconds
    When client sends request to resolve DID document
    Then check success response contains "#did"
    When client sends request to deactivate DID document
    Then we wait 1 seconds
    When client sends request to resolve DID document
    Then check error response contains "document is no longer available"

  @create_recover_did_doc
  Scenario: recover did doc
    When client sends request to create DID document
    Then check success response contains "#did"
    Then we wait 1 seconds
    When client sends request to resolve DID document
    Then check success response contains "#did"

    When client sends request to recover DID document with "resolution" error
    Then we wait 1 seconds
    When client sends request to resolve DID document
    Then check success response contains "#emptydoc"

    When client sends request to recover DID document
    Then we wait 1 seconds
    When client sends request to resolve DID document
    Then check success response contains "recoveryKey"

    When client sends request to recover DID document with "request" error
    Then check error response contains "missing delta"

    @create_add_remove_public_key
    Scenario: add and remove public keys
      When client sends request to create DID document
      Then check success response contains "#did"
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
      Then check success response contains "#did"
      Then we wait 1 seconds
      When client sends request to add service endpoint with ID "newService" to DID document
      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "newService"
      When client sends request to remove service endpoint with ID "newService" from DID document
      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response does NOT contain "newService"
      When client sends request to update DID document with "request" error
      Then check error response contains "missing delta"

    @update_doc_error
    Scenario: handle update document errors
      When client sends request to create DID document
      Then check success response contains "#did"
      Then we wait 1 seconds
      When client sends request to update DID document with "resolution" error
      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "#did"
      Then check success response contains "createKey"
      When client sends request to update DID document with "request" error
      Then check error response contains "missing delta"



