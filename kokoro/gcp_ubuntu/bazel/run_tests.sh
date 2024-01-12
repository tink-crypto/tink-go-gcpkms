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

# Builds and tests tink-go-gcpkms using Bazel.
#
# The behavior of this script can be modified using the following optional env
# variables:
#
# - CONTAINER_IMAGE (unset by default): By default when run locally this script
#   executes tests directly on the host. The CONTAINER_IMAGE variable can be set
#   to execute tests in a custom container image for local testing. E.g.:
#
#   CONTAINER_IMAGE="us-docker.pkg.dev/tink-test-infrastructure/tink-ci-images/linux-tink-go-base:latest" \
#     sh ./kokoro/gcp_ubuntu/bazel/run_tests.sh
set -euo pipefail

RUN_COMMAND_ARGS=()
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
  readonly TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_go_gcpkms"
  source "./kokoro/testutils/go_test_container_images.sh"
  CONTAINER_IMAGE="${TINK_GO_BASE_IMAGE}"
  RUN_COMMAND_ARGS+=( -k "${TINK_GCR_SERVICE_KEY}" )
fi
readonly CONTAINER_IMAGE

if [[ -n "${CONTAINER_IMAGE:-}" ]]; then
  RUN_COMMAND_ARGS+=( -c "${CONTAINER_IMAGE}" )
fi

./kokoro/testutils/copy_credentials.sh "testdata" "gcp"

cat <<'EOF' > _do_run_test.sh
#!/bin/bash

set -euo pipefail

./kokoro/testutils/check_go_generated_files_up_to_date.sh "$(pwd)"

MANUAL_TARGETS=()
# Run manual tests that rely on test data only available via Bazel.
if [[ -n "${KOKORO_ROOT:-}" ]]; then
  MANUAL_TARGETS+=( "//integration/gcpkms:gcpkms_test" )
fi
readonly MANUAL_TARGETS

./kokoro/testutils/run_bazel_tests.sh -t --test_arg=--test.v . \
  "${MANUAL_TARGETS[@]}"

./kokoro/testutils/run_bazel_tests.sh -b --enable_bzlmod \
  -t --enable_bzlmod,--test_arg=--test.v . "${MANUAL_TARGETS[@]}"
EOF
chmod +x _do_run_test.sh

cat <<EOF > _env_variables.txt
KOKORO_ROOT
EOF
RUN_COMMAND_ARGS+=( -e _env_variables.txt )

# Run cleanup on EXIT.
trap cleanup EXIT

cleanup() {
  rm -rf _do_run_test.sh
  rm -rf _env_variables.txt
}

./kokoro/testutils/run_command.sh "${RUN_COMMAND_ARGS[@]}" ./_do_run_test.sh
