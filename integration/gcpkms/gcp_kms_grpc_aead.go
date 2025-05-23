// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcpkms

import (
	"context"
	"fmt"
	"strings"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	"cloud.google.com/go/kms/apiv1"

	"github.com/tink-crypto/tink-go/v2/tink"
)

// grpcAEAD represents a GCP GRPC-based KMS client to a particular URI.
type grpcAEAD struct {
	keyURI string
	kms    *kms.KeyManagementClient
}

var _ tink.AEADWithContext = (*grpcAEAD)(nil)

// newGRPCAEAD returns a new GCP KMS client.
func newGRPCAEAD(keyURI string, kms *kms.KeyManagementClient) tink.AEADWithContext {
	return &grpcAEAD{
		keyURI: keyURI,
		kms:    kms,
	}
}

// EncryptWithContext encrypts the plaintext with associatedData.
func (a *grpcAEAD) EncryptWithContext(ctx context.Context, plaintext, associatedData []byte) ([]byte, error) {

	req := &kmspb.EncryptRequest{
		Name:                              a.keyURI,
		Plaintext:                         plaintext,
		PlaintextCrc32C:                   wrapperspb.Int64(computeChecksum(plaintext)),
		AdditionalAuthenticatedData:       associatedData,
		AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(computeChecksum(associatedData)),
	}

	resp, err := a.kms.Encrypt(ctx, req)

	if err != nil {
		return nil, err
	}
	if !resp.VerifiedPlaintextCrc32C {
		return nil, fmt.Errorf("KMS request for %q is missing the checksum field plaintext_crc32c, and other information may be missing from the response. Please retry a limited number of times in case the error is transient", a.keyURI)
	}
	if !resp.VerifiedAdditionalAuthenticatedDataCrc32C {
		return nil, fmt.Errorf("KMS request for %q is missing the checksum field additional_authenticated_data_crc32c, and other information may be missing from the response. Please retry a limited number of times in case the error is transient", a.keyURI)
	}
	if !strings.HasPrefix(resp.GetName(), a.keyURI) {
		return nil, fmt.Errorf("the requested key name %q does not match the key name in the KMS response %q", a.keyURI, resp.GetName())
	}
	if resp.CiphertextCrc32C.GetValue() != computeChecksum(resp.Ciphertext) {
		return nil, fmt.Errorf("KMS response corrupted in transit for %q: the checksum in field ciphertext_crc32c did not match the data in field ciphertext. Please retry in case this is a transient error", a.keyURI)
	}

	return resp.Ciphertext, nil
}

// DecryptWithContext decrypts ciphertext with associatedData.
func (a *grpcAEAD) DecryptWithContext(ctx context.Context, ciphertext, associatedData []byte) ([]byte, error) {

	req := &kmspb.DecryptRequest{
		Name:                              a.keyURI,
		Ciphertext:                        ciphertext,
		CiphertextCrc32C:                  wrapperspb.Int64(computeChecksum(ciphertext)),
		AdditionalAuthenticatedData:       associatedData,
		AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(computeChecksum(associatedData)),
	}

	resp, err := a.kms.Decrypt(ctx, req)

	if err != nil {
		return nil, err
	}
	if resp.PlaintextCrc32C.GetValue() != computeChecksum(resp.Plaintext) {
		return nil, fmt.Errorf("KMS response corrupted in transit for %q: the checksum in field plaintext_crc32c did not match the data in field plaintext. Please retry in case this is a transient error", a.keyURI)
	}

	return resp.Plaintext, nil
}

type aeadWithContextWrapper struct {
	tink.AEADWithContext
}

var _ tink.AEAD = (*aeadWithContextWrapper)(nil)

func (w *aeadWithContextWrapper) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return w.EncryptWithContext(context.TODO(), plaintext, associatedData)
}

func (w *aeadWithContextWrapper) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return w.DecryptWithContext(context.TODO(), ciphertext, associatedData)
}
