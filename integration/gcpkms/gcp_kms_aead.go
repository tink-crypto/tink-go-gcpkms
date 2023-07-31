// Copyright 2017 Google Inc.
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
//
////////////////////////////////////////////////////////////////////////////////

package gcpkms

import (
	"context"
	"errors"
	"hash/crc32"

	kms "cloud.google.com/go/kms/apiv1"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// gcpAEAD represents a GCP KMS service to a particular URI.
type gcpAEAD struct {
	keyURI string
	kms    kms.KeyManagementClient
}

var _ tink.AEAD = (*gcpAEAD)(nil)

// newGCPAEAD returns a new GCP KMS service.
func newGCPAEAD(keyURI string, kms *kms.KeyManagementClient) tink.AEAD {
	return &gcpAEAD{
		keyURI: keyURI,
		kms:    *kms,
	}
}

// Encrypt encrypts the plaintext with associatedData.
func (a *gcpAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	plaintextCRC32C := crc32c(plaintext)
	associatedDataCRC32C := crc32c(associatedData)

	req := &kmspb.EncryptRequest{
		Name:                              a.keyURI,
		Plaintext:                         plaintext,
		PlaintextCrc32C:                   wrapperspb.Int64(int64(plaintextCRC32C)),
		AdditionalAuthenticatedData:       associatedData,
		AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(int64(associatedDataCRC32C)),
	}

	ctx := context.Background()
	resp, err := a.kms.Encrypt(ctx, req)
	if err != nil {
		return nil, err
	}

	// Perform integrity verification on result.
	if !resp.VerifiedPlaintextCrc32C {
		return nil, errors.New("Encrypt: request corrupted in-transit")
	}
	if int64(crc32c(resp.Ciphertext)) != resp.CiphertextCrc32C.Value {
		return nil, errors.New("Encrypt: response corrupted in-transit")
	}

	return resp.Ciphertext, nil
}

// Decrypt decrypts ciphertext with with associatedData.
func (a *gcpAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	ciphertextCRC32C := crc32c(ciphertext)
	associatedDataCRC32C := crc32c(associatedData)

	req := &kmspb.DecryptRequest{
		Name:                              a.keyURI,
		Ciphertext:                        ciphertext,
		CiphertextCrc32C:                  wrapperspb.Int64(int64(ciphertextCRC32C)),
		AdditionalAuthenticatedData:       associatedData,
		AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(int64(associatedDataCRC32C)),
	}

	ctx := context.Background()
	resp, err := a.kms.Decrypt(ctx, req)
	if err != nil {
		return nil, err
	}

	// Perform integrity verification on result.
	if int64(crc32c(resp.Plaintext)) != resp.PlaintextCrc32C.Value {
		return nil, errors.New("Decrypt: response corrupted in-transit")
	}

	return resp.Plaintext, nil
}

// Compute text's CRC32C.
func crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}
