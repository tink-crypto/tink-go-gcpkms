#!/bin/bash
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

# The user may specify TINK_BASE_DIR as the folder where to look for
# tink-go-gcpkms dependencies.

set -euo pipefail

TINK_GO_GCPKMS_PROJECT_PATH="$(pwd)"
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  TINK_GO_GCPKMS_PROJECT_PATH="${TINK_BASE_DIR}/tink_go_gcpkms"
  cd "${TINK_GO_GCPKMS_PROJECT_PATH}"
fi
readonly TINK_GO_GCPKMS_PROJECT_PATH

: "${TINK_BASE_DIR:=$(cd .. && pwd)}"

# Check for dependencies in TINK_BASE_DIR. Any that aren't present will be
# downloaded.
readonly GITHUB_ORG="https://github.com/tink-crypto"
./kokoro/testutils/fetch_git_repo_if_not_present.sh "${TINK_BASE_DIR}" \
  "${GITHUB_ORG}/tink-go"

./kokoro/testutils/copy_credentials.sh "testdata" "gcp"
# Sourcing required to update callers environment.
source ./kokoro/testutils/install_go.sh

echo "Using go binary from $(which go): $(go version)"

readonly TINK_GO_MODULE_URL="github.com/tink-crypto/tink-go/v2"
readonly TINK_GO_GCPKMS_MODULE_URL="github.com/tink-crypto/tink-go-gcpkms"
readonly TINK_VERSION="$(cat ${TINK_GO_GCPKMS_PROJECT_PATH}/version.bzl \
                        | grep ^TINK \
                        | cut -f 2 -d \")"


cp go.mod go.mod.bak

# Modify go.mod locally to use the version of tink-go in TINK_BASE_DIR/tink_go.
go mod edit "-replace=${TINK_GO_MODULE_URL}=${TINK_BASE_DIR}/tink_go"
go mod tidy
go list -m all | grep tink-go

./kokoro/testutils/run_go_mod_tests.sh \
  "${TINK_GO_GCPKMS_MODULE_URL}" \
  "${TINK_GO_GCPKMS_PROJECT_PATH}" \
  "${TINK_VERSION}" \
  "main"

mv go.mod.bak go.mod
