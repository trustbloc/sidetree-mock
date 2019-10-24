#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e


echo -e  "[SAN]\nsubjectAltName=DNS:*.example.com,DNS:localhost" >> /etc/ssl/openssl.cnf

echo "Generating sidetree-mock Test PKI"
cd /opt/go/src/github.com/trustbloc/sidetree-mock
mkdir -p test/bddtests/fixtures/keys/tls

#create CA
openssl ecparam -name prime256v1 -genkey -noout -out test/bddtests/fixtures/keys/tls/ec-cakey.pem
openssl req -new -x509 -key test/bddtests/fixtures/keys/tls/ec-cakey.pem -subj "/C=CA/ST=ON/O=Example Internet CA Inc.:CA Sec/OU=CA Sec" -out test/bddtests/fixtures/keys/tls/ec-cacert.pem

#create TLS creds
openssl ecparam -name prime256v1 -genkey -noout -out test/bddtests/fixtures/keys/tls/ec-key.pem
openssl req -new -key test/bddtests/fixtures/keys/tls/ec-key.pem -subj "/C=CA/ST=ON/O=Example Inc.:sidetree-mock/OU=sidetree-mock/CN=*.example.com" -reqexts SAN -out test/bddtests/fixtures/keys/tls/ec-key.csr
openssl x509 -req -in test/bddtests/fixtures/keys/tls/ec-key.csr -extensions SAN -CA test/bddtests/fixtures/keys/tls/ec-cacert.pem -CAkey test/bddtests/fixtures/keys/tls/ec-cakey.pem -CAcreateserial -out test/bddtests/fixtures/keys/tls/ec-pubCert.pem -days 365


echo "done generating sidetree-mock PKI"
