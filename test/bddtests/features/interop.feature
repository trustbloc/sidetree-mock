#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Each test has to be run on fresh system since create document is the same for all tests
@did_interop
Feature:

    @interop_longform_create_update_doc
    Scenario: interop test for create/update operations and long form DID resolution
      When client sends "long-form-did" resolve request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/vectors/generated.json"
      Then success response matches resolution result "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/vectors/resolution/longFormResponseDidDocument.json"

      When client sends "create" operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/vectors/generated.json"
      Then success response is validated against resolution result "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/vectors/resolution/afterCreate.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then success response matches resolution result "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/vectors/resolution/afterCreate.json"

      When client sends "update" operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/vectors/generated.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then success response matches resolution result "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/vectors/resolution/afterUpdate.json"

    @interop_create_recover_deactivate_doc
    Scenario: interop test for recover/deactivate operations
      When client sends "create" operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/vectors/generated.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "#did"

      When client sends "recover" operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/vectors/generated.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then success response matches resolution result "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/vectors/resolution/afterRecover.json"

      When client sends "deactivate" operation request from "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/vectors/generated.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check error response contains "deactivated"

      #Then error response matches resolution result "https://raw.githubusercontent.com/decentralized-identity/sidetree/master/tests/vectors/resolution/afterDeactivate.json"

