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

# By default when run locally this script runs the command below directly on the
# host. The CONTAINER_IMAGE variable can be set to run on a custom container
# image for local testing. E.g.:
#
# CONTAINER_IMAGE="gcr.io/tink-test-infrastructure/linux-tink-go-base:latest" \
#  sh ./kokoro/gcp_ubuntu/gomod/run_tests.sh
#
# The user may specify TINK_BASE_DIR as the folder where to look for
# tink-go-gcpkms and its dependencies. That is:
#   ${TINK_BASE_DIR}/tink_go
#   ${TINK_BASE_DIR}/tink_go_gcpkms
# NOTE: tink_go is fetched from GitHub if not found.
set -eEuo pipefail

RUN_COMMAND_ARGS=()
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  readonly C_PREFIX="us-docker.pkg.dev/tink-test-infrastructure/tink-ci-images"
  readonly C_NAME="linux-tink-go-base"
  readonly C_HASH="2fddb51977a951759ab3b87643b672d590f277fe6ade5787fa8721dd91ea839a"
  CONTAINER_IMAGE="${C_PREFIX}/${C_NAME}@sha256:${C_HASH}"
  RUN_COMMAND_ARGS+=( -k "${TINK_GCR_SERVICE_KEY}" )
fi
: "${TINK_BASE_DIR:=$(cd .. && pwd)}"
readonly TINK_BASE_DIR
readonly CONTAINER_IMAGE

# If running from the tink_go_gcpkms folder this has no effect.
cd "${TINK_BASE_DIR}/tink_go_gcpkms"

if [[ -n "${CONTAINER_IMAGE:-}" ]]; then
  RUN_COMMAND_ARGS+=( -c "${CONTAINER_IMAGE}" )
fi

# Check for dependencies in TINK_BASE_DIR. Any that aren't present will be
# downloaded.
readonly GITHUB_ORG="https://github.com/tink-crypto"
./kokoro/testutils/fetch_git_repo_if_not_present.sh "${TINK_BASE_DIR}" \
  "${GITHUB_ORG}/tink-go"

./kokoro/testutils/copy_credentials.sh "testdata" "gcp"

readonly TINK_GO_MODULE_URL="github.com/tink-crypto/tink-go/v2"
readonly TINK_GO_GCPKMS_MODULE_URL="github.com/tink-crypto/tink-go-gcpkms"
readonly TINK_VERSION="$(cat version.bzl | grep ^TINK | cut -f 2 -d \")"

cp go.mod go.mod.bak

cat <<EOF > _do_run_test.sh
set -euo pipefail

# Modify go.mod locally to use the version of tink-go in ../tink_go.
go mod edit "-replace=${TINK_GO_MODULE_URL}=../tink_go"
go mod tidy
go list -m all | grep tink-go
./kokoro/testutils/run_go_mod_tests.sh "${TINK_GO_GCPKMS_MODULE_URL}" . \
  "${TINK_VERSION}" "main"
EOF
chmod +x _do_run_test.sh

# Run cleanup on EXIT.
trap cleanup EXIT

cleanup() {
  mv go.mod.bak go.mod
  rm -rf _do_run_test.sh
}

./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" ./_do_run_test.sh
