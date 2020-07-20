#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did-interop
Feature:

    @interop_resolve_with_initial_value
    Scenario: resolve document with initial value
      When client sends interop resolve with initial value request
      Then check success response contains "EiBFsUlzmZ3zJtSFeQKwJNtngjmB51ehMWWDuptf9b4Bag"

    @interop_create_doc
    Scenario: create valid did doc
      When client sends interop operation request from "fixtures/interop/create.json"
      Then check success response contains "EiBFsUlzmZ3zJtSFeQKwJNtngjmB51ehMWWDuptf9b4Bag"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "#didDocumentHash"
      Then check success response contains "signingKey"

    @interop_deactivate_doc
    Scenario: interop test for deactivate operation
      When client sends interop operation request from "fixtures/interop/deactivate/create.json"
      Then check success response contains "EiBKP-cspvQlz8eymq6kOtIo8awHFAhZomJtsGF_QS9KqA"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "#didDocumentHash"

      When client sends interop operation request from "fixtures/interop/deactivate/deactivate.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check error response contains "document is no longer available"

    @interop_recover_doc
    Scenario: interop test for recover operation
      When client sends interop operation request from "fixtures/interop/recover/create.json"
      Then check success response contains "EiAdHUPfyqtr9d-NBYwwMHCzryLaTYVAyZl4Hu9GvrupYQ"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "#didDocumentHash"

      When client sends interop operation request from "fixtures/interop/recover/recover.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "#didDocumentHash"
      Then check success response contains "newKey"

    @interop_update_doc
    Scenario: interop test for update operation
      When client sends interop operation request from "fixtures/interop/update/create.json"
      Then check success response contains "EiDpoi14bmEVVUp-woMgEruPyPvVEMtOsXtyo51eQ0Tdig"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "#didDocumentHash"

      When client sends interop operation request from "fixtures/interop/update/update.json"

      Then we wait 1 seconds
      When client sends request to resolve DID document
      Then check success response contains "#didDocumentHash"
      Then check success response contains "new-key1"
