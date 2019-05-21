#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

if [[ ! -e ./swagger ]]; then
    url=https://github.com/go-swagger/go-swagger/releases/download/v0.18.0/swagger_$(uname | tr '[:upper:]' '[:lower:]')_amd64
    echo "Downloading go-swagger binary from: ${url}"
    curl -so swagger -L'#' ${url}
    chmod +x swagger
fi

./swagger generate server --spec=api/swagger.yaml
