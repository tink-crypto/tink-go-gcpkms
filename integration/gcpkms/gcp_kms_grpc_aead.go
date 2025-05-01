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

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
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
//
// TODO: b/308189580 - Add integrity verification.
func (a *grpcAEAD) EncryptWithContext(ctx context.Context, plaintext, associatedData []byte) ([]byte, error) {

	req := &kmspb.EncryptRequest{
		Name:                        a.keyURI,
		Plaintext:                   plaintext,
		AdditionalAuthenticatedData: associatedData,
	}
	resp, err := a.kms.Encrypt(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.Ciphertext, nil
}

// DecryptWithContext decrypts ciphertext with with associatedData.
//
// TODO: b/308189580 - Add integrity verification.
func (a *grpcAEAD) DecryptWithContext(ctx context.Context, ciphertext, associatedData []byte) ([]byte, error) {

	req := &kmspb.DecryptRequest{
		Name:                        a.keyURI,
		Ciphertext:                  ciphertext,
		AdditionalAuthenticatedData: associatedData,
	}
	resp, err := a.kms.Decrypt(ctx, req)
	if err != nil {
		return nil, err
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
