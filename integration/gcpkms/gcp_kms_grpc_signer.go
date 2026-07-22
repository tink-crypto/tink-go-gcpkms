// Copyright 2025 Google LLC
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
	"crypto"
	"crypto/sha3"
	"errors"
	"fmt"
	"strings"

	"cloud.google.com/go/kms/apiv1"
	"github.com/tink-crypto/tink-go/v2/tink"

	// Placeholder for internal proto import.
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	mldsa44PublicKeyBytes = 1312
	mldsa65PublicKeyBytes = 1952
	mldsa87PublicKeyBytes = 2592
	// mldsaPublicKeyHashBytes is the size in bytes of tr = SHAKE256(public key, 64).
	mldsaPublicKeyHashBytes = 64
	// mldsaMuBytes is the size in bytes of the ML-DSA external-mu message representative (μ).
	mldsaMuBytes = 64
)

// GRPCSigner represents a GCP gRPC-based KMS client for a particular key URI.
type GRPCSigner struct {
	keyName   string
	kms       *kms.KeyManagementClient
	publicKey *kmspb.PublicKey
	// mldsaPublicKeyHash is tr = SHAKE256(public key, 64) for external-mu ML-DSA keys, or nil for
	// all other algorithms.
	mldsaPublicKeyHash []byte
}

var _ tink.Signer = (*GRPCSigner)(nil)

// kmsMaxSignDataSize represents the maximum size of the data that can be signed.
const kmsMaxSignDataSize = 64 * 1024

// isSupported reports whether the given algorithm is supported for signing.
func isSupported(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) bool {
	switch algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_ED25519,
		kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384,
		kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512,
		kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048,
		kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_3072,
		kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_4096,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87,
		kmspb.CryptoKeyVersion_PQ_SIGN_SLH_DSA_SHA2_128S,
		kmspb.CryptoKeyVersion_PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44_EXTERNAL_MU,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87_EXTERNAL_MU:

		return true
	}
	return false
}

// useNISTPQCFormat reports whether the public key must be (re-)fetched in NIST_PQC format.
//
// This is needed in two cases:
//   - The key does not support PEM at all (e.g. SLH-DSA), which surfaces as an error.
//   - The algorithm is external-mu ML-DSA, where the raw NIST_PQC key bytes are required to
//     compute the message representative (μ).
//
// All other algorithms, including regular ML-DSA, are fully served by the initial PEM response.
func useNISTPQCFormat(response *kmspb.PublicKey, err error) bool {
	if err != nil && strings.Contains(err.Error(), "Only NIST_PQC format is supported") {
		return true
	}
	if err == nil && isMLDSAExternalMuAlgorithm(response.GetAlgorithm()) {
		return true
	}
	return false
}

// requiresDataForSign reports whether the given algorithm and protection level require
// raw data as signing input rather than a computed digest.
func requiresDataForSign(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, protectionLevel kmspb.ProtectionLevel) bool {
	switch algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_ED25519,
		kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048,
		kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_3072,
		kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_4096,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87,
		kmspb.CryptoKeyVersion_PQ_SIGN_SLH_DSA_SHA2_128S:

		return true
	}
	switch protectionLevel {
	case kmspb.ProtectionLevel_EXTERNAL, kmspb.ProtectionLevel_EXTERNAL_VPC:
		return true
	}
	return false
}

// NewGRPCSigner returns a new GCP KMS client that can be used for signing.
func NewGRPCSigner(ctx context.Context, keyName string, kms *kms.KeyManagementClient) (*GRPCSigner, error) {
	if err := validateKMSKeyName(keyName); err != nil {
		return nil, err
	}
	if kms == nil {
		return nil, errors.New("kms client cannot be nil")
	}
	publicKey, err := getPublicKey(ctx, keyName, kms, useNISTPQCFormat)
	if err != nil {
		return nil, err
	}
	if !isSupported(publicKey.GetAlgorithm()) {
		return nil, fmt.Errorf("the given algorithm %q is not supported", publicKey.GetAlgorithm())
	}
	var mldsaPublicKeyHash []byte
	if isMLDSAExternalMuAlgorithm(publicKey.GetAlgorithm()) {
		mldsaPublicKeyHash, err = computeMLDSAPublicKeyHash(publicKey)
		if err != nil {
			return nil, err
		}
	}
	return &GRPCSigner{
		keyName:            keyName,
		kms:                kms,
		publicKey:          publicKey,
		mldsaPublicKeyHash: mldsaPublicKeyHash,
	}, nil
}

// digestHashForAlgorithm returns the crypto.Hash associated with the given KMS algorithm.
func digestHashForAlgorithm(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (crypto.Hash, error) {
	switch algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		kmspb.CryptoKeyVersion_PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256:

		return crypto.SHA256, nil
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return crypto.SHA384, nil
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:

		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("algorithm %q does not support digests", algorithm)
	}
}

// isMLDSAExternalMuAlgorithm returns whether the algorithm expects an externally computed ML-DSA
// message representative (μ) rather than a plain digest of the data.
func isMLDSAExternalMuAlgorithm(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) bool {
	switch algorithm {
	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44_EXTERNAL_MU,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87_EXTERNAL_MU:

		return true
	}
	return false
}

// getMLDSAPublicKeySize returns the encoded public key size for an external-mu ML-DSA algorithm.
func getMLDSAPublicKeySize(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (int, error) {
	switch algorithm {
	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44_EXTERNAL_MU:
		return mldsa44PublicKeyBytes, nil
	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU:
		return mldsa65PublicKeyBytes, nil
	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87_EXTERNAL_MU:
		return mldsa87PublicKeyBytes, nil
	default:
		return 0, fmt.Errorf("the given algorithm %q does not support an external ML-DSA mu", algorithm)
	}
}

// computeMLDSAPublicKeyHash computes the SHAKE-256 hash of the public key for an external-mu ML-DSA key.
//
// Per FIPS-204:
//
//	tr = SHAKE256(public key, 64)
func computeMLDSAPublicKeyHash(publicKey *kmspb.PublicKey) ([]byte, error) {
	publicKeyBytes := publicKey.GetPublicKey().GetData()
	expectedSize, err := getMLDSAPublicKeySize(publicKey.GetAlgorithm())
	if err != nil {
		return nil, err
	}
	if len(publicKeyBytes) != expectedSize {
		return nil, fmt.Errorf("incorrect public key size for %q: got %d bytes, want %d", publicKey.GetAlgorithm(), len(publicKeyBytes), expectedSize)
	}
	return sha3.SumSHAKE256(publicKeyBytes, mldsaPublicKeyHashBytes), nil
}

// computeMLDSAExternalMu computes the ML-DSA message representative (μ) for the empty context used
// by Cloud KMS.
//
// Per FIPS-204 (algorithm 7 in section 6.2):
//
//	μ = SHAKE256(tr || 0x00 || 0x00 || data, 64)
//
// Where tr is the SHAKE-256 hash of the encoded public key. KMS signs with an empty context,
// so μ is computed with an empty context as well.
func computeMLDSAExternalMu(publicKeyHash, data []byte) []byte {
	h := sha3.NewSHAKE256()
	h.Write(publicKeyHash)
	h.Write([]byte{0x00, 0x00}) // Pure-mode domain separator and empty-context length.
	h.Write(data)
	mu := make([]byte, mldsaMuBytes)
	h.Read(mu)
	return mu
}

// calculateDigest returns the digest of the given data and the CRC32C checksum of the digest.
// It returns an error if the digest cannot be computed.
func (s *GRPCSigner) calculateDigest(data []byte) (*kmspb.Digest, int64, error) {
	if isMLDSAExternalMuAlgorithm(s.publicKey.GetAlgorithm()) {
		mu := computeMLDSAExternalMu(s.mldsaPublicKeyHash, data)
		digest := &kmspb.Digest{Digest: &kmspb.Digest_ExternalMu{ExternalMu: mu}}
		return digest, computeChecksum(mu), nil
	}

	selectedHash, err := digestHashForAlgorithm(s.publicKey.GetAlgorithm())
	if err != nil {
		return nil, 0, err
	}
	if !selectedHash.Available() {
		return nil, 0, fmt.Errorf("hash function %v is not available", selectedHash)
	}

	h := selectedHash.New()
	h.Write(data)
	digestBytes := h.Sum(nil)

	digest := &kmspb.Digest{}
	switch selectedHash {
	case crypto.SHA256:
		digest.Digest = &kmspb.Digest_Sha256{Sha256: digestBytes}
	case crypto.SHA384:
		digest.Digest = &kmspb.Digest_Sha384{Sha384: digestBytes}
	case crypto.SHA512:
		digest.Digest = &kmspb.Digest_Sha512{Sha512: digestBytes}
	default:
		return nil, 0, fmt.Errorf("unsupported hash function %v", selectedHash)
	}
	checksum := computeChecksum(digestBytes)
	return digest, checksum, nil
}

// buildAsymmetricSignRequest constructs an AsymmetricSignRequest for the given data.
func (s *GRPCSigner) buildAsymmetricSignRequest(data []byte) (*kmspb.AsymmetricSignRequest, error) {
	request := &kmspb.AsymmetricSignRequest{Name: s.keyName}
	if requiresDataForSign(s.publicKey.GetAlgorithm(), s.publicKey.GetProtectionLevel()) {
		if len(data) > kmsMaxSignDataSize {
			return nil, fmt.Errorf("the input data (%d bytes) is larger than the allowed limit (%d bytes)", len(data), kmsMaxSignDataSize)
		}
		request.Data = data
		checksum := computeChecksum(data)
		request.DataCrc32C = &wrapperspb.Int64Value{Value: checksum}
		return request, nil
	}

	digest, digestCrc32C, err := s.calculateDigest(data)
	if err != nil {
		return nil, err
	}

	request.Digest = digest
	request.DigestCrc32C = &wrapperspb.Int64Value{Value: digestCrc32C}
	return request, nil
}

// Sign calls KMS to sign the input data and returns the signature.
func (s *GRPCSigner) Sign(data []byte) ([]byte, error) {
	return s.SignWithContext(context.TODO(), data)
}

// SignWithContext calls KMS to sign the input data and returns the signature.
func (s *GRPCSigner) SignWithContext(ctx context.Context, data []byte) ([]byte, error) {
	request, err := s.buildAsymmetricSignRequest(data)
	if err != nil {
		return nil, err
	}

	response, err := s.kms.AsymmetricSign(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS AsymmetricSign failed: %w", err)
	}

	// Perform integrity checks
	if response.GetName() != s.keyName {
		return nil, fmt.Errorf("the response key name %q does not match the requested key name %q", response.GetName(), s.keyName)
	}

	// Since we only request data OR digest for signing, we expect that exactly
	// one of the checksum fields is verified.
	if !response.GetVerifiedDataCrc32C() && !response.GetVerifiedDigestCrc32C() {
		return nil, errors.New("checking the input checksum failed")
	}

	computedChecksumSignature := computeChecksum(response.GetSignature())
	if response.GetSignatureCrc32C().GetValue() != computedChecksumSignature {
		return nil, errors.New("signature checksum mismatch")
	}

	return response.GetSignature(), nil
}
