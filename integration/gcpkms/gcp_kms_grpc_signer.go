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
	"errors"
	"fmt"
	"regexp"

	"cloud.google.com/go/kms/apiv1"

	// Placeholder for internal proto import.
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

// GRPCSigner represent a GCP GRPC-based KMS client to a particular key URI.
type GRPCSigner struct {
	keyName   string
	kms       *kms.KeyManagementClient
	publicKey *kmspb.PublicKey
}

// Maximum size of the data that can be signed.
var kmsMaxSignDataSize = 64 * 1024
var kmsKeyNameRegex = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[^/]+$`)

var errorChecksumMismatch = errors.New("checksum verification failed")

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
		kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_4096:

		return true
	}
	return false
}

// Some AsymmetricSign algorithms require data as input and some other
// operate on a digest of the data. This method determines if data itself is
// required for signing and returns true if so.
func requiresDataForSign(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, protectionLevel kmspb.ProtectionLevel) bool {
	switch algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_ED25519,
		kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048,
		kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_3072,
		kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_4096:

		return true
	}
	switch protectionLevel {
	case kmspb.ProtectionLevel_EXTERNAL, kmspb.ProtectionLevel_EXTERNAL_VPC:
		return true
	}
	return false
}

// tryGetPublicKey tries to get the public key for the given key name.
// Requires that the request explicitly specifies the key format.
func tryGetPublicKey(ctx context.Context, kms *kms.KeyManagementClient, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	if req.GetPublicKeyFormat() == kmspb.PublicKey_PUBLIC_KEY_FORMAT_UNSPECIFIED {
		return nil, fmt.Errorf("public key format is required")
	}
	response, err := kms.GetPublicKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS GetPublicKey failed: %w", err)
	}
	checksumReceived := response.GetPublicKey().GetCrc32CChecksum().GetValue()
	checksumCalculated := computeChecksum(response.GetPublicKey().GetData())
	if checksumReceived != checksumCalculated {
		return nil, fmt.Errorf("%w: recieved %d, calculated %d", errorChecksumMismatch, checksumReceived, checksumCalculated)
	}
	return response, nil
}

// getPublicKey gets the public key for the given key name.
func getPublicKey(ctx context.Context, keyName string, kms *kms.KeyManagementClient) (*kmspb.PublicKey, error) {
	req := &kmspb.GetPublicKeyRequest{Name: keyName, PublicKeyFormat: kmspb.PublicKey_PEM}
	var response *kmspb.PublicKey
	var err error
	// The goal is to retry a limited number of times on checksum validation errors in case the error
	// is transient, following the guidelines in https://cloud.google.com/kms/docs/data-integrity-guidelines
	for i := 0; i < 3; i++ {
		response, err = tryGetPublicKey(ctx, kms, req)
		if err != nil && errors.Is(err, errorChecksumMismatch) {
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

// NewGRPCSigner returns a new GCP KMS client that can be used for signing.
func NewGRPCSigner(ctx context.Context, keyName string, kms *kms.KeyManagementClient) (*GRPCSigner, error) {
	if !kmsKeyNameRegex.MatchString(keyName) {
		return nil, fmt.Errorf("keyName %q does not match the expected format %q", keyName, kmsKeyNameRegex.String())
	}
	if kms == nil {
		return nil, fmt.Errorf("kms client cannot be nil")
	}
	publicKey, err := getPublicKey(ctx, keyName, kms)
	if err != nil {
		return nil, err
	}
	if !isSupported(publicKey.GetAlgorithm()) {
		return nil, fmt.Errorf("the given algorithm %q is not supported", publicKey.GetAlgorithm())
	}
	return &GRPCSigner{
		keyName:   keyName,
		kms:       kms,
		publicKey: publicKey,
	}, nil
}

func digestHashForAlgorithm(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (crypto.Hash, error) {
	switch algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:

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

// calculateDigest returns the digest of the given data and the CRC32C checksum of the digest.
// It returns an error if the digest cannot be computed.
func calculateDigest(data []byte, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (*kmspb.Digest, int64, error) {
	selectedHash, err := digestHashForAlgorithm(algorithm)
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

func buildAsymmetricSignRequest(keyName string, data []byte, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, protectionLevel kmspb.ProtectionLevel) (*kmspb.AsymmetricSignRequest, error) {
	request := &kmspb.AsymmetricSignRequest{Name: keyName}
	if requiresDataForSign(algorithm, protectionLevel) {
		request.Data = data
		checksum := computeChecksum(data)
		request.DataCrc32C = &wrapperspb.Int64Value{Value: checksum}
		return request, nil
	}

	digest, digestCrc32C, err := calculateDigest(data, algorithm)
	if err != nil {
		return nil, err
	}

	request.Digest = digest
	request.DigestCrc32C = &wrapperspb.Int64Value{Value: digestCrc32C}
	return request, nil
}

// SignWithContext calls KMS to sign the input data and returns the signature.
func (signer *GRPCSigner) SignWithContext(ctx context.Context, data []byte) ([]byte, error) {
	if len(data) > kmsMaxSignDataSize {
		return nil, fmt.Errorf("the input data (%d bytes) is larger than the allowed limit (%d bytes)", len(data), kmsMaxSignDataSize)
	}

	request, err := buildAsymmetricSignRequest(signer.keyName, data, signer.publicKey.GetAlgorithm(), signer.publicKey.GetProtectionLevel())
	if err != nil {
		return nil, err
	}

	response, err := signer.kms.AsymmetricSign(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS AsymmetricSign failed: %w", err)
	}

	// Perform integrity checks
	if response.GetName() != signer.keyName {
		return nil, fmt.Errorf("the response key name %q does not match the requested key name %q", response.GetName(), signer.keyName)
	}

	// Since we only request data OR digest for signing, we expect that exactly
	// one of the checksum fields is verified.
	if !response.GetVerifiedDataCrc32C() && !response.GetVerifiedDigestCrc32C() {
		return nil, fmt.Errorf("checking the input checksum failed: %w", err)
	}

	computedChecksumSignature := computeChecksum(response.GetSignature())
	if response.GetSignatureCrc32C().GetValue() != computedChecksumSignature {
		return nil, fmt.Errorf("signature checksum mismatch: %w", err)
	}

	return response.GetSignature(), nil
}
