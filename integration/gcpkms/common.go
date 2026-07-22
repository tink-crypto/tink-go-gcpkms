// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcpkms

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"cloud.google.com/go/kms/apiv1"

	// Placeholder for internal proto import.
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

const (
	kmsKeyNamePattern = `^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[^/]+$`
)

var (
	kmsKeyNameRegex = regexp.MustCompile(kmsKeyNamePattern)
)

var errChecksumMismatch = errors.New("checksum verification failed")

func validateKMSKeyName(keyName string) error {
	if !kmsKeyNameRegex.MatchString(keyName) {
		return fmt.Errorf("keyName %q does not match the expected format %q", keyName, kmsKeyNamePattern)
	}
	return nil
}

// tryGetPublicKey attempts to get the public key for the given key name.
// It requires that the request explicitly specifies the key format.
func tryGetPublicKey(ctx context.Context, kms *kms.KeyManagementClient, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	if req.GetPublicKeyFormat() == kmspb.PublicKey_PUBLIC_KEY_FORMAT_UNSPECIFIED {
		return nil, errors.New("public key format is required")
	}
	response, err := kms.GetPublicKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS GetPublicKey failed: %w", err)
	}
	checksumReceived := response.GetPublicKey().GetCrc32CChecksum().GetValue()
	checksumCalculated := computeChecksum(response.GetPublicKey().GetData())
	if checksumReceived != checksumCalculated {
		return nil, fmt.Errorf("%w: received %d, calculated %d", errChecksumMismatch, checksumReceived, checksumCalculated)
	}
	return response, nil
}

// getPublicKey gets the public key for the given key name.
//
// The initial request is made in PEM format; needsNISTPQC decides, from the PEM response or error,
// whether the key must be (re-)fetched in NIST_PQC format instead. Since needsNISTPQC is called even
// when tryGetPublicKey returns an error, implementations of needsNISTPQC must be nil-safe for the
// *kmspb.PublicKey argument (which will be nil if an error occurs). This lets the signer and verifier
// share the fetch and integrity logic while selecting the format each one needs.
func getPublicKey(ctx context.Context, keyName string, kms *kms.KeyManagementClient, needsNISTPQC func(*kmspb.PublicKey, error) bool) (*kmspb.PublicKey, error) {
	req := &kmspb.GetPublicKeyRequest{Name: keyName, PublicKeyFormat: kmspb.PublicKey_PEM}
	var response *kmspb.PublicKey
	var err error
	// The goal is to retry a limited number of times on checksum validation errors in case the error
	// is transient, following the guidelines in https://cloud.google.com/kms/docs/data-integrity-guidelines
	for i := 0; i < 3; i++ {
		response, err = tryGetPublicKey(ctx, kms, req)
		if req.PublicKeyFormat != kmspb.PublicKey_NIST_PQC && needsNISTPQC(response, err) {
			req.PublicKeyFormat = kmspb.PublicKey_NIST_PQC
			response, err = tryGetPublicKey(ctx, kms, req)
		}
		if err != nil && errors.Is(err, errChecksumMismatch) {
			continue
		}
		break
	}
	if err != nil {
		return nil, err
	}
	if response.GetName() != keyName {
		return nil, fmt.Errorf("the response key name %q does not match the requested key name %q", response.GetName(), keyName)
	}
	return response, nil
}
