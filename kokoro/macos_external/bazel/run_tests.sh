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

if [[ -n "${KOKORO_ROOT:-}" ]]; then
  cd "${KOKORO_ARTIFACTS_DIR}/git/tink_go_gcpkms"
  use_bazel.sh "$(cat .bazelversion)"
fi

: "${TINK_BASE_DIR:=$(cd .. && pwd)}"

# Check for dependencies in TINK_BASE_DIR. Any that aren't present will be
# downloaded.
readonly GITHUB_ORG="https://github.com/tink-crypto"
./kokoro/testutils/fetch_git_repo_if_not_present.sh "${TINK_BASE_DIR}" \
  "${GITHUB_ORG}/tink-go"

# Sourcing required to update callers environment.
source ./kokoro/testutils/install_go.sh

echo "Using go binary from $(which go): $(go version)"

# TODO(b/238389921): Run check_go_generated_files_up_to_date.sh after a
# refactoring that takes into account extensions to tink-go.

./kokoro/testutils/copy_credentials.sh "testdata" "gcp"

# Replace com_github_tink_crypto_tink_go with a local one.
grep -r "com_github_tink_crypto_tink_go" -l --include="*.bazel"  . \
  | xargs sed -i '.bak' \
      "s~com_github_tink_crypto_tink_go~com_github_tink_crypto_tink_go_local~g"

sed -i '.bak' \
  's~workspace(name = "tink_go_gcpkms")~workspace(name = "tink_go_gcpkms")\
\
local_repository(\
    name = "com_github_tink_crypto_tink_go_local",\
    path = "'"${TINK_BASE_DIR}"'/tink_go",\
)~' WORKSPACE

MANUAL_TARGETS=()
# Run manual tests that rely on test data only available via Bazel.
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  MANUAL_TARGETS+=( "//integration/gcpkms:gcpkms_test" )
fi
readonly MANUAL_TARGETS

./kokoro/testutils/run_bazel_tests.sh . "${MANUAL_TARGETS[@]}"

mv WORKSPACE.bak WORKSPACE
