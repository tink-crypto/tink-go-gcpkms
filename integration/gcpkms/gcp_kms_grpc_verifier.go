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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"cloud.google.com/go/kms/apiv1"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkecdsa "github.com/tink-crypto/tink-go/v2/signature/ecdsa"
	tinkmldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
	tinkrsapkcs1 "github.com/tink-crypto/tink-go/v2/signature/rsassapkcs1"
	tinkrsapss "github.com/tink-crypto/tink-go/v2/signature/rsassapss"
	"github.com/tink-crypto/tink-go/v2/signature"
	tinkslhdsa "github.com/tink-crypto/tink-go/v2/signature/slhdsa"
	"github.com/tink-crypto/tink-go/v2/tink"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"  // injected by Copybara
	// Placeholder for internal proto import.
)

// GRPCVerifier is a [tink.Verifier] backed by a GCP KMS asymmetric signing key.
//
// The public key is fetched (or supplied) once at construction and all verification is performed
// locally; Verify makes no KMS calls.
type GRPCVerifier struct {
	verifier tink.Verifier
}

var _ tink.Verifier = (*GRPCVerifier)(nil)

// NewGRPCVerifier returns a new GRPCVerifier for the given key version name.
//
// It fetches the public key from GCP KMS, validates the response integrity, and builds a local
// verifier. After construction no KMS calls are made.
func NewGRPCVerifier(ctx context.Context, keyName string, kms *kms.KeyManagementClient) (*GRPCVerifier, error) {
	if err := validateKMSKeyName(keyName); err != nil {
		return nil, err
	}
	if kms == nil {
		return nil, errors.New("kms client cannot be nil")
	}
	publicKey, err := getPublicKey(ctx, keyName, kms, verifierNeedsNISTPQCFormat)
	if err != nil {
		return nil, err
	}
	verifier, err := internalVerifier(publicKey.GetAlgorithm(), publicKey.GetPublicKey().GetData())
	if err != nil {
		return nil, err
	}
	return &GRPCVerifier{verifier: verifier}, nil
}

// NewGRPCVerifierFromPublicKey returns a new GRPCVerifier from pre-fetched public key material,
// without contacting GCP KMS.
//
// The argument publicKey must be the exact bytes returned by GCP KMS for the given algorithm
// (PEM for classical algorithms) and algorithm must match.
//
// Unlike NewGRPCVerifier, this path cannot verify the KMS response checksum or key name, so the
// caller is responsible for the integrity and provenance of the supplied public key material.
func NewGRPCVerifierFromPublicKey(publicKey []byte, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (*GRPCVerifier, error) {
	if len(publicKey) == 0 {
		return nil, errors.New("the public key is empty")
	}
	verifier, err := internalVerifier(algorithm, publicKey)
	if err != nil {
		return nil, err
	}
	return &GRPCVerifier{verifier: verifier}, nil
}

// Verify verifies that signatureBytes is a valid signature of data. It returns nil if the signature
// is valid and an error otherwise.
func (v *GRPCVerifier) Verify(signatureBytes, data []byte) error {
	return v.verifier.Verify(signatureBytes, data)
}

// verifierNeedsNISTPQCFormat reports whether the verifier must (re-)fetch the public key in NIST_PQC format.
//
// Classical algorithms are fully served by the PEM response. Post-quantum algorithms are
// served as either raw NIST_PQC bytes or PEM format.
// But the verifier processes raw bytes, so PQC keys are refetched in NIST_PQC.
func verifierNeedsNISTPQCFormat(response *kmspb.PublicKey, err error) bool {
	if err != nil {
		return strings.Contains(err.Error(), "Only NIST_PQC format is supported")
	}
	return isPQCAlgorithm(response.GetAlgorithm())
}

// internalVerifier builds a local [tink.Verifier] for the given KMS algorithm and public key
// material. The algorithm mapping also acts as the support check: unsupported algorithms fail here.
func internalVerifier(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, publicKeyData []byte) (tink.Verifier, error) {
	var publicKey key.Key
	var err error
	if isPQCAlgorithm(algorithm) {
		publicKey, err = pqcPublicKey(algorithm, publicKeyData)
	} else {
		publicKey, err = classicalPublicKey(algorithm, publicKeyData)
	}
	if err != nil {
		return nil, err
	}
	return verifierFromKey(publicKey)
}

// isPQCAlgorithm reports whether the algorithm's public key is served as raw NIST_PQC bytes and
// verified through the post-quantum path.
func isPQCAlgorithm(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) bool {
	switch algorithm {
	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44_EXTERNAL_MU,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87_EXTERNAL_MU,
		kmspb.CryptoKeyVersion_PQ_SIGN_SLH_DSA_SHA2_128S:

		return true
	}
	return false
}

// pqcPublicKey builds the Tink signature public key for a post-quantum algorithm from the raw
// NIST_PQC public key bytes returned by GCP KMS. The algorithm switch also acts as the support check.
//
// External-mu ML-DSA keys map to the same instance as their base algorithm: an external-mu signature
// is a standard ML-DSA signature (the KMS signer and the pure verifier compute the message
// representative μ identically), so it is verified through the same pure ML-DSA path.
func pqcPublicKey(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, rawPublicKey []byte) (key.Key, error) {
	switch algorithm {
	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44_EXTERNAL_MU:
		return mldsaPublicKey(rawPublicKey, tinkmldsa.MLDSA44)
	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU:
		return mldsaPublicKey(rawPublicKey, tinkmldsa.MLDSA65)
	case kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87,
		kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87_EXTERNAL_MU:
		return mldsaPublicKey(rawPublicKey, tinkmldsa.MLDSA87)
	case kmspb.CryptoKeyVersion_PQ_SIGN_SLH_DSA_SHA2_128S:
		return slhdsaPublicKey(rawPublicKey)
	default:
		return nil, fmt.Errorf("the given algorithm %q is not supported", algorithm)
	}
}

// mldsaPublicKey builds a Tink ML-DSA public key from raw NIST_PQC material. KMS produces raw ML-DSA
// signatures with no Tink output prefix, hence the NO_PREFIX variant.
func mldsaPublicKey(rawPublicKey []byte, instance tinkmldsa.Instance) (key.Key, error) {
	params, err := tinkmldsa.NewParameters(instance, tinkmldsa.VariantNoPrefix)
	if err != nil {
		return nil, err
	}
	// NewPublicKey validates the key length for the instance, catching a key/algorithm mismatch.
	return tinkmldsa.NewPublicKey(rawPublicKey, 0, params)
}

// slhdsaPublicKey builds a Tink SLH-DSA-SHA2-128s public key from raw NIST_PQC material. KMS produces
// raw SLH-DSA signatures with no Tink output prefix, hence the NO_PREFIX variant.
func slhdsaPublicKey(rawPublicKey []byte) (key.Key, error) {
	params, err := tinkslhdsa.NewParameters(tinkslhdsa.SHA2, 64, tinkslhdsa.SmallSignature, tinkslhdsa.VariantNoPrefix)
	if err != nil {
		return nil, err
	}
	// NewPublicKey validates the key length, catching a key/algorithm mismatch.
	return tinkslhdsa.NewPublicKey(rawPublicKey, 0, params)
}

// classicalPublicKey builds the Tink signature public key for a classical (ECDSA or RSA) algorithm
// from the PEM-encoded public key material returned by GCP KMS. The algorithm switch also acts as
// the support check: unsupported algorithms fail here before the material is parsed.
func classicalPublicKey(algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, pemPublicKey []byte) (key.Key, error) {
	switch algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		return ecdsaPublicKey(pemPublicKey, tinkecdsa.NistP256, tinkecdsa.SHA256)
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		return ecdsaPublicKey(pemPublicKey, tinkecdsa.NistP384, tinkecdsa.SHA384)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256:
		return rsaPKCS1PublicKey(pemPublicKey, 2048, tinkrsapkcs1.SHA256)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256:
		return rsaPKCS1PublicKey(pemPublicKey, 3072, tinkrsapkcs1.SHA256)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		return rsaPKCS1PublicKey(pemPublicKey, 4096, tinkrsapkcs1.SHA256)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		return rsaPKCS1PublicKey(pemPublicKey, 4096, tinkrsapkcs1.SHA512)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256:
		return rsaPSSPublicKey(pemPublicKey, 2048, tinkrsapss.SHA256, 32)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256:
		return rsaPSSPublicKey(pemPublicKey, 3072, tinkrsapss.SHA256, 32)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256:
		return rsaPSSPublicKey(pemPublicKey, 4096, tinkrsapss.SHA256, 32)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512:
		return rsaPSSPublicKey(pemPublicKey, 4096, tinkrsapss.SHA512, 64)
	default:
		return nil, fmt.Errorf("the given algorithm %q is not supported", algorithm)
	}
}

// parsePEMPublicKey decodes a PEM block and parses the DER-encoded PKIX public key inside it.
func parsePEMPublicKey(pemPublicKey []byte) (any, error) {
	block, _ := pem.Decode(pemPublicKey)
	if block == nil {
		return nil, errors.New("failed to decode PEM block from the public key")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the public key: %w", err)
	}
	return parsedKey, nil
}

// ecdsaPublicKey builds a Tink ECDSA public key from PEM material. KMS emits DER-encoded ECDSA
// signatures with no Tink output prefix, so the key uses DER encoding and the NO_PREFIX variant.
func ecdsaPublicKey(pemPublicKey []byte, curve tinkecdsa.CurveType, hash tinkecdsa.HashType) (key.Key, error) {
	parsedKey, err := parsePEMPublicKey(pemPublicKey)
	if err != nil {
		return nil, err
	}
	pub, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("the public key is not an ECDSA key: got %T", parsedKey)
	}
	pubBytes, err := pub.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize the ECDSA public key: %w", err)
	}
	params, err := tinkecdsa.NewParameters(curve, hash, tinkecdsa.DER, tinkecdsa.VariantNoPrefix)
	if err != nil {
		return nil, err
	}
	// NewPublicKey validates the point against the curve, catching a key/algorithm mismatch.
	return tinkecdsa.NewPublicKey(pubBytes, 0, params)
}

// rsaPKCS1PublicKey builds a Tink RSA SSA PKCS1 public key from PEM material.
func rsaPKCS1PublicKey(pemPublicKey []byte, modulusSizeBits int, hash tinkrsapkcs1.HashType) (key.Key, error) {
	pub, err := rsaPublicKey(pemPublicKey)
	if err != nil {
		return nil, err
	}
	params, err := tinkrsapkcs1.NewParameters(modulusSizeBits, hash, pub.E, tinkrsapkcs1.VariantNoPrefix)
	if err != nil {
		return nil, err
	}
	// NewPublicKey validates the modulus bit-length, catching a key/algorithm mismatch.
	return tinkrsapkcs1.NewPublicKey(pub.N.Bytes(), 0, params)
}

// rsaPSSPublicKey builds a Tink RSA SSA PSS public key from PEM material. KMS uses the signature hash
// for MGF1 and a salt length equal to the hash length.
func rsaPSSPublicKey(pemPublicKey []byte, modulusSizeBits int, hash tinkrsapss.HashType, saltLengthBytes int) (key.Key, error) {
	pub, err := rsaPublicKey(pemPublicKey)
	if err != nil {
		return nil, err
	}
	params, err := tinkrsapss.NewParameters(tinkrsapss.ParametersValues{
		ModulusSizeBits: modulusSizeBits,
		SigHashType:     hash,
		MGF1HashType:    hash,
		PublicExponent:  pub.E,
		SaltLengthBytes: saltLengthBytes,
	}, tinkrsapss.VariantNoPrefix)
	if err != nil {
		return nil, err
	}
	// NewPublicKey validates the modulus bit-length, catching a key/algorithm mismatch.
	return tinkrsapss.NewPublicKey(pub.N.Bytes(), 0, params)
}

// rsaPublicKey parses PEM material and asserts it is an RSA public key.
func rsaPublicKey(pemPublicKey []byte) (*rsa.PublicKey, error) {
	parsedKey, err := parsePEMPublicKey(pemPublicKey)
	if err != nil {
		return nil, err
	}
	pub, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("the public key is not an RSA key: got %T", parsedKey)
	}
	return pub, nil
}

// verifierFromKey wraps a single public key in a keyset and returns a [tink.Verifier] for it. KMS
// produces raw algorithm signatures without a Tink output prefix, hence the keys use NO_PREFIX.
func verifierFromKey(publicKey key.Key) (tink.Verifier, error) {
	manager := keyset.NewManager()
	keyID, err := manager.AddKey(publicKey)
	if err != nil {
		return nil, err
	}
	if err := manager.SetPrimary(keyID); err != nil {
		return nil, err
	}
	handle, err := manager.Handle()
	if err != nil {
		return nil, err
	}
	return signature.NewVerifier(handle)
}
