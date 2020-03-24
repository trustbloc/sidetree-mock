#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e


echo "Generating sidetree-mock Test PKI"

# TODO re-use the sandbox CA script https://github.com/trustbloc/sidetree-mock/issues/131
cd /opt/workspace/sidetree-mock
mkdir -p test/bddtests/fixtures/keys/tls
tmp=$(mktemp)
echo "subjectKeyIdentifier=hash
authorityKeyIdentifier = keyid,issuer
extendedKeyUsage = serverAuth
keyUsage = Digital Signature, Key Encipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost" >> "$tmp"

#create CA
openssl ecparam -name prime256v1 -genkey -noout -out test/bddtests/fixtures/keys/tls/ec-cakey.pem
openssl req -new -x509 -key test/bddtests/fixtures/keys/tls/ec-cakey.pem -subj "/C=CA/ST=ON/O=Example Internet CA Inc.:CA Sec/OU=CA Sec" -out test/bddtests/fixtures/keys/tls/ec-cacert.pem

#create TLS creds
openssl ecparam -name prime256v1 -genkey -noout -out test/bddtests/fixtures/keys/tls/ec-key.pem
openssl req -new -key test/bddtests/fixtures/keys/tls/ec-key.pem -subj "/C=CA/ST=ON/O=Example Inc.:sidtree-mock/OU=sidtree-mock/CN=localhost" -out test/bddtests/fixtures/keys/tls/ec-key.csr
openssl x509 -req -in test/bddtests/fixtures/keys/tls/ec-key.csr -CA test/bddtests/fixtures/keys/tls/ec-cacert.pem -CAkey test/bddtests/fixtures/keys/tls/ec-cakey.pem -CAcreateserial -extfile "$tmp" -out test/bddtests/fixtures/keys/tls/ec-pubCert.pem -days 365


echo "done generating sidetree-mock PKI"
