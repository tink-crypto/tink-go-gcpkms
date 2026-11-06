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
	"crypto/ed25519"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinked25519 "github.com/tink-crypto/tink-go/v2/signature/ed25519"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"  // injected by Copybara
	// Placeholder for internal proto import.
)

// VerificationKey is a public key returned by Cloud KMS FetchVerificationKeys.
type VerificationKey struct {
	PublicKeyPEM []byte
	Algorithm    kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
}

// NewPublicKeysetHandle creates a public [keyset.Handle] from the (PEM,
// algorithm) pairs returned by Cloud KMS FetchVerificationKeys, without calling
// KMS. Keys are imported with no output prefix and DER signature encoding for
// ECDSA; the first key is the primary. Callers unpacking
// FetchVerificationKeysResponse should paginate next_page_token, verify each
// key's crc32c_checksum, and order keys newest-first so the newest version is
// primary.
//
// It accepts the algorithms of [NewGRPCVerifierFromPublicKey] (plus
// EC_SIGN_ED25519) except SLH-DSA. Any unsupported or invalid key returns an
// error, so callers migrating off an unsupported algorithm must filter those
// versions out first.
//
// Warning: This API is in preview and may change in the future.
func NewPublicKeysetHandle(keys []VerificationKey) (*keyset.Handle, error) {
	if len(keys) == 0 {
		return nil, errors.New("no verification keys given")
	}
	manager := keyset.NewManager()
	for i, verificationKey := range keys {
		publicKey, err := publicKeyFromPEM(verificationKey.Algorithm, verificationKey.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("verification key %d (%v): %w", i, verificationKey.Algorithm, err)
		}
		keyID, err := manager.AddKey(publicKey)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			if err := manager.SetPrimary(keyID); err != nil {
				return nil, err
			}
		}
	}
	return manager.Handle()
}

func publicKeyFromPEM(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, pemPublicKey []byte) (key.Key, error) {
	if algorithm == kmspb.CryptoKeyVersion_EC_SIGN_ED25519 {
		return ed25519PublicKey(pemPublicKey)
	}
	if wantOID, ok := mldsaSPKIOIDs[algorithm]; ok {
		rawPublicKey, err := mldsaRawPublicKeyFromPEM(algorithm, wantOID, pemPublicKey)
		if err != nil {
			return nil, err
		}
		return pqcPublicKey(algorithm, rawPublicKey)
	}
	return classicalPublicKey(algorithm, pemPublicKey)
}

func ed25519PublicKey(pemPublicKey []byte) (key.Key, error) {
	parsedKey, err := parsePEMPublicKey(pemPublicKey)
	if err != nil {
		return nil, err
	}
	pub, ok := parsedKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("the public key is not an Ed25519 key: got %T", parsedKey)
	}
	params, err := tinked25519.NewParameters(tinked25519.VariantNoPrefix)
	if err != nil {
		return nil, err
	}
	return tinked25519.NewPublicKey(pub, 0, params)
}

var mldsaSPKIOIDs = map[kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm]asn1.ObjectIdentifier{
	kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44:             {2, 16, 840, 1, 101, 3, 4, 3, 17},
	kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44_EXTERNAL_MU: {2, 16, 840, 1, 101, 3, 4, 3, 17},
	kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65:             {2, 16, 840, 1, 101, 3, 4, 3, 18},
	kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU: {2, 16, 840, 1, 101, 3, 4, 3, 18},
	kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87:             {2, 16, 840, 1, 101, 3, 4, 3, 19},
	kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87_EXTERNAL_MU: {2, 16, 840, 1, 101, 3, 4, 3, 19},
}

// TODO: b/543948981 - Use x509.ParsePKIXPublicKey once Go 1.27 (https://go.dev/issue/78888) is required.
func mldsaRawPublicKeyFromPEM(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, wantOID asn1.ObjectIdentifier, pemPublicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(pemPublicKey)
	if block == nil {
		return nil, errors.New("failed to decode PEM block from the public key")
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(block.Bytes, &spki)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the public key: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("failed to parse the public key: trailing data after SubjectPublicKeyInfo")
	}
	if !spki.Algorithm.Algorithm.Equal(wantOID) {
		return nil, fmt.Errorf("the public key algorithm OID %v does not match %q", spki.Algorithm.Algorithm, algorithm)
	}
	if len(spki.Algorithm.Parameters.FullBytes) != 0 {
		return nil, errors.New("the ML-DSA public key must not have algorithm parameters")
	}
	if spki.PublicKey.BitLength%8 != 0 {
		return nil, errors.New("the ML-DSA public key is not a whole number of bytes")
	}
	return spki.PublicKey.Bytes, nil
}
