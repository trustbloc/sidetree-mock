#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Each test has to be run on fresh system since create document is the same for all tests
@did-interop
Feature:

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
      Then check success response contains "#did"

      When client sends operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/deactivate/deactivate.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check error response contains "document is no longer available"

    @interop_recover_doc
    Scenario: interop test for recover operation
      When client sends operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/recover/create.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "#did"

      When client sends operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/recover/recover.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then success response is validated against resolution result "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/recover/resultingDocument.json"

    @interop_update_doc
    Scenario: interop test for update operation
      When client sends operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/update/create.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "#did"

      When client sends operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/update/update.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then success response is validated against resolution result "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/update/resultingDocument.json"

    @interop_resolve_long_form_did
    Scenario: interop test for resolving long form did
      When client sends resolve request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/longFormDid/longFormDid.txt"
      Then success response is validated against resolution result "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/fixtures/longFormDid/resultingDocument.json"
