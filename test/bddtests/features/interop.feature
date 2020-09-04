#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Each test has to be run on fresh system since create document is the same for all tests
@did-interop
Feature:

    @interop_resolve_with_initial_value
    Scenario: resolve document with initial value
      When client sends interop resolve with initial value request
      Then check success response contains "EiBFsUlzmZ3zJtSFeQKwJNtngjmB51ehMWWDuptf9b4Bag"

    @interop_create_doc
    Scenario: create valid did doc
      When client sends operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/create/create.json"
      Then success response is validated against resolution result "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/create/resultingDocument.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then success response is validated against resolution result "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/create/resultingDocument.json"

    @interop_deactivate_doc
    Scenario: interop test for deactivate operation
      When client sends operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/deactivate/create.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "#didDocumentHash"

      When client sends operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/deactivate/deactivate.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check error response contains "document is no longer available"

    @interop_recover_doc
    Scenario: interop test for recover operation
      When client sends operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/recover/create.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "#didDocumentHash"

      When client sends operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/recover/recover.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then success response is validated against resolution result "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/recover/resultingDocument.json"

    @interop_update_doc
    Scenario: interop test for update operation
      When client sends operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/update/create.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "#didDocumentHash"

      When client sends operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/update/update.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then success response is validated against resolution result "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/update/resultingDocument.json"
