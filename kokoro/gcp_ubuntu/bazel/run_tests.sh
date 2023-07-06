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
#  sh ./kokoro/gcp_ubuntu/bazel/run_tests.sh
#
# The user may specify TINK_BASE_DIR as the folder where to look for
# tink-go-gcpkms and its dependencies. That is:
#   ${TINK_BASE_DIR}/tink_go
#   ${TINK_BASE_DIR}/tink_go_gcpkms
# NOTE: tink_go is fetched from GitHub if not found.
set -euo pipefail

RUN_COMMAND_ARGS=()
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
  TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  source \
    "${TINK_BASE_DIR}/tink_go_gcpkms/kokoro/testutils/go_test_container_images.sh"
  CONTAINER_IMAGE="${TINK_GO_BASE_IMAGE}"
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

# TODO(b/238389921): Run check_go_generated_files_up_to_date.sh after a
# refactoring that takes into account extensions to tink-go.
./kokoro/testutils/copy_credentials.sh "testdata" "gcp"

cp WORKSPACE WORKSPACE.bak

# Replace com_github_tink_crypto_tink_go_v2 with a local one.
mapfile -d '' TINK_GO_LOCAL_REPO <<'EOF'
local_repository(\
    name = "com_github_tink_crypto_tink_go_v2",\
    path = "../tink_go",\
)\
EOF
readonly TINK_GO_LOCAL_REPO

mapfile -d '' TINK_GO_DEPENDENCIES <<'EOF'
load("@com_github_tink_crypto_tink_go_v2//:deps.bzl", tink_go_dependencies="go_dependencies")\
\
tink_go_dependencies()\
EOF
readonly TINK_GO_DEPENDENCIES

sed -i \
  "s~# Placeholder for tink-go http_archive or local_repository.~${TINK_GO_LOCAL_REPO}~" \
  WORKSPACE
sed -i \
  "s~# Placeholder for tink-go dependencies.~${TINK_GO_DEPENDENCIES}~"\
  WORKSPACE

MANUAL_TARGETS=()
# Run manual tests that rely on test data only available via Bazel.
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  MANUAL_TARGETS+=( "//integration/gcpkms:gcpkms_test" )
fi
readonly MANUAL_TARGETS

trap cleanup EXIT

cleanup() {
  mv WORKSPACE.bak WORKSPACE
}

./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" \
  ./kokoro/testutils/run_bazel_tests.sh \
    -t --test_arg=--test.v . "${MANUAL_TARGETS[@]}"
