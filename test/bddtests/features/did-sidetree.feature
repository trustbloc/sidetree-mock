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
    When client discover endpoints
    When client sends request to create DID document
    Then check success response contains "#did"
    # retrieve document with initial value before it becomes available on the ledger
    When client sends request to resolve DID document with initial state
    Then check success response contains "#did"
    # retrieve document with initial value and alias before it becomes available on the ledger
    When client sends request to resolve DID document with initial state and with alias "did:sidetree:domain.com"
    # Then check success response contains "#aliasdid"
    # we wait until observer poll sidetree txn from ledger
    Then we wait 2 seconds
    When client sends request to resolve DID document
    Then check success response contains "#did"
    When client sends request to resolve DID document with alias "did:sidetree:domain.com"
    Then check success response contains "#did"
    Then check success response contains "#aliasdid"
    When client sends request to resolve DID document with alias "did:notconfigured.com"
    Then check error response contains "did must start with configured namespace[did:sidetree] or aliases[did:sidetree:alias.com did:sidetree:domain.com]"

    # retrieve document with initial value after it becomes available on the ledger
    When client sends request to resolve DID document with initial state
    Then check success response contains "#did"

    # retrieve document with initial value and alias after it becomes available on the ledger
    When client sends request to resolve DID document with initial state and with alias "did:sidetree:domain.com"
    Then check success response contains "#did"
    Then check success response contains "#aliasdid"

    When client sends request to create DID document with "patch" error
    Then check error response contains "applying delta resulted in an empty document (most likely due to an invalid patch)"

    When client sends request to create DID document with "request" error
    Then check error response contains "missing delta"

  @create_deactivate_did_doc
  Scenario: deactivate valid did doc
    When client discover endpoints
    When client sends request to create DID document
    Then check success response contains "#did"
    Then we wait 2 seconds
    When client sends request to resolve DID document
    Then check success response contains "#did"
    When client sends request to deactivate DID document
    Then we wait 2 seconds
    When client sends request to resolve DID document
    Then check success response contains "deactivated"

  @create_recover_did_doc
  Scenario: recover did doc
    When client discover endpoints
    When client sends request to create DID document
    Then check success response contains "#did"
    Then we wait 2 seconds
    When client sends request to resolve DID document
    Then check success response contains "#did"

    When client sends request to recover DID document with "resolution" error
    Then we wait 2 seconds
    When client sends request to resolve DID document
    Then check success response contains "#emptydoc"

    When client sends request to recover DID document
    Then we wait 2 seconds
    When client sends request to resolve DID document
    Then check success response contains "recoveryKey"

    When client sends request to recover DID document with "request" error
    Then check error response contains "missing delta"

    @create_add_remove_public_key
    Scenario: add and remove public keys
      When client discover endpoints
      When client sends request to create DID document
      Then check success response contains "#did"
      Then we wait 2 seconds
      When client sends request to add public key with ID "newKey" to DID document
      Then we wait 2 seconds
      When client sends request to resolve DID document
      Then check success response contains "newKey"
      When client sends request to remove public key with ID "newKey" from DID document
      Then we wait 2 seconds
      When client sends request to resolve DID document
      Then check success response does NOT contain "newKey"

    @create_add_remove_services
    Scenario: add and remove service endpoints
      When client discover endpoints
      When client sends request to create DID document
      Then check success response contains "#did"
      Then we wait 2 seconds
      When client sends request to add service endpoint with ID "newService" to DID document
      Then we wait 2 seconds
      When client sends request to resolve DID document
      Then check success response contains "newService"
      When client sends request to remove service endpoint with ID "newService" from DID document
      Then we wait 2 seconds
      When client sends request to resolve DID document
      Then check success response does NOT contain "newService"
      When client sends request to update DID document with "request" error
      Then check error response contains "missing delta"

    @create_update_also_known_as
    Scenario: update also known as
      When client discover endpoints
      When client sends request to create DID document
      Then check success response contains "#did"
      Then we wait 2 seconds
      When client sends request to update DID document path "/alsoKnownAs" with value "different.com"
      Then we wait 2 seconds
      When client sends request to resolve DID document
      Then check success response contains "different.com"

    @update_doc_error
    Scenario: handle update document errors
      When client discover endpoints
      When client sends request to create DID document
      Then check success response contains "#did"
      Then we wait 2 seconds
      When client sends request to update DID document with "resolution" error
      Then we wait 2 seconds
      When client sends request to resolve DID document
      Then check success response contains "#did"
      Then check success response contains "createKey"
      When client sends request to update DID document with "request" error
      Then check error response contains "missing delta"

  @reuse_keys_for_did_operations
  Scenario: reuse keys for did operations
    When client discover endpoints
    When client sets reuse keys for did operations to "true"

    When client sends request to create DID document
    Then check success response contains "#did"
    Then we wait 2 seconds

    When client sends request to add public key with ID "newKey" to DID document
    Then we wait 2 seconds
    When client sends request to resolve DID document
    Then check success response contains "newKey"

    When client sends request to recover DID document
    Then we wait 2 seconds
    When client sends request to resolve DID document
    Then check success response contains "recoveryKey"

    When client sends request to add public key with ID "newKey2" to DID document
    Then we wait 2 seconds
    When client sends request to resolve DID document
    Then check success response contains "newKey2"

    When client sends request to deactivate DID document
    Then we wait 2 seconds
    When client sends request to resolve DID document
    Then check success response contains "deactivated"

    # reset flag back to false for other tests
    When client sets reuse keys for did operations to "false"
