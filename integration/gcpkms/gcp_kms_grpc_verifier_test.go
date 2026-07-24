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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkmldsa "github.com/tink-crypto/tink-go/v2/signature/mldsa"
	"github.com/tink-crypto/tink-go/v2/signature"
	tinkslhdsa "github.com/tink-crypto/tink-go/v2/signature/slhdsa"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"  // injected by Copybara
	// Placeholder for internal proto import.
)

const (
	verifyKeyNameECP256                    = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/1"
	verifyKeyNameECP384                    = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/2"
	verifyKeyNameRSAPKCS12048              = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/3"
	verifyKeyNameRSAPKCS13072              = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/4"
	verifyKeyNameRSAPKCS14096SHA256        = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/5"
	verifyKeyNameRSAPKCS14096SHA512        = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/6"
	verifyKeyNameRSAPSS2048                = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/7"
	verifyKeyNameRSAPSS3072                = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/8"
	verifyKeyNameRSAPSS4096SHA256          = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/9"
	verifyKeyNameRSAPSS4096SHA512          = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/10"
	verifyKeyNameErrorGetPublicKey         = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/11"
	verifyKeyNameErrorChecksumMismatch     = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/12"
	verifyKeyNameErrorWrongKeyName         = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/13"
	verifyKeyNameErrorUnsupportedAlgorithm = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/14"
	verifyKeyNameMLDSA44                   = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/15"
	verifyKeyNameMLDSA65                   = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/16"
	verifyKeyNameMLDSA87                   = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/17"
	verifyKeyNameSLHDSA                    = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/18"
	verifyKeyNameMLDSA44ExternalMu         = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/19"
	verifyKeyNameMLDSA65ExternalMu         = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/20"
	verifyKeyNameMLDSA87ExternalMu         = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K2/cryptoKeyVersions/21"
)

// verifyMessage is the message signed and verified across the verifier tests.
var verifyMessage = []byte("data to verify")

// classicalTestKey holds generated material for one classical verifier test key: the KMS algorithm,
// the KMS-shaped PEM public key, and a signer producing KMS-shaped signatures over a message.
type classicalTestKey struct {
	algorithm    kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	pemPublicKey []byte
	sign         func(t *testing.T, message []byte) []byte
}

type pqcTestKey struct {
	algorithm    kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	rawPublicKey []byte
	nistPQCOnly  bool
	sign         func(t *testing.T, message []byte) []byte
}

var (
	verifierClassicalKeys     map[string]classicalTestKey
	verifierClassicalKeysOnce sync.Once

	verifierPQCKeys     map[string]pqcTestKey
	verifierPQCKeysOnce sync.Once
)

func getVerifierClassicalKeys(t *testing.T) map[string]classicalTestKey {
	t.Helper()
	verifierClassicalKeysOnce.Do(func() {
		rsaKey2048 := generateRSA(t, 2048)
		rsaKey3072 := generateRSA(t, 3072)
		rsaKey4096 := generateRSA(t, 4096)

		verifierClassicalKeys = map[string]classicalTestKey{
			verifyKeyNameECP256:             newECDSATestKey(t, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, elliptic.P256(), crypto.SHA256),
			verifyKeyNameECP384:             newECDSATestKey(t, kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, elliptic.P384(), crypto.SHA384),
			verifyKeyNameRSAPKCS12048:       newRSAPKCS1TestKey(t, kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, rsaKey2048, crypto.SHA256),
			verifyKeyNameRSAPKCS13072:       newRSAPKCS1TestKey(t, kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256, rsaKey3072, crypto.SHA256),
			verifyKeyNameRSAPKCS14096SHA256: newRSAPKCS1TestKey(t, kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256, rsaKey4096, crypto.SHA256),
			verifyKeyNameRSAPKCS14096SHA512: newRSAPKCS1TestKey(t, kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512, rsaKey4096, crypto.SHA512),
			verifyKeyNameRSAPSS2048:         newRSAPSSTestKey(t, kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256, rsaKey2048, crypto.SHA256),
			verifyKeyNameRSAPSS3072:         newRSAPSSTestKey(t, kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256, rsaKey3072, crypto.SHA256),
			verifyKeyNameRSAPSS4096SHA256:   newRSAPSSTestKey(t, kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256, rsaKey4096, crypto.SHA256),
			verifyKeyNameRSAPSS4096SHA512:   newRSAPSSTestKey(t, kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512, rsaKey4096, crypto.SHA512),
		}
	})
	return verifierClassicalKeys
}

func getVerifierPQCKeys(t *testing.T) map[string]pqcTestKey {
	t.Helper()
	verifierPQCKeysOnce.Do(func() {
		verifierPQCKeys = map[string]pqcTestKey{
			verifyKeyNameMLDSA44: newPQCTestKey(t, kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44, mldsaParams(t, tinkmldsa.MLDSA44), false),
			verifyKeyNameMLDSA65: newPQCTestKey(t, kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65, mldsaParams(t, tinkmldsa.MLDSA65), false),
			verifyKeyNameMLDSA87: newPQCTestKey(t, kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87, mldsaParams(t, tinkmldsa.MLDSA87), false),
			verifyKeyNameSLHDSA:  newPQCTestKey(t, kmspb.CryptoKeyVersion_PQ_SIGN_SLH_DSA_SHA2_128S, slhdsaParams(t), true),
			verifyKeyNameMLDSA44ExternalMu: newPQCTestKey(t, kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44_EXTERNAL_MU, mldsaParams(t, tinkmldsa.MLDSA44), false),
			verifyKeyNameMLDSA65ExternalMu: newPQCTestKey(t, kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU, mldsaParams(t, tinkmldsa.MLDSA65), false),
			verifyKeyNameMLDSA87ExternalMu: newPQCTestKey(t, kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87_EXTERNAL_MU, mldsaParams(t, tinkmldsa.MLDSA87), false),
		}
	})
	return verifierPQCKeys
}

// mldsaParams builds NO_PREFIX ML-DSA parameters for the given instance or signals test failure.
func mldsaParams(t *testing.T, instance tinkmldsa.Instance) key.Parameters {
	t.Helper()
	params, err := tinkmldsa.NewParameters(instance, tinkmldsa.VariantNoPrefix)
	if err != nil {
		t.Fatalf("tinkmldsa.NewParameters(%v, VariantNoPrefix) err = %v, want nil", instance, err)
	}
	return params
}

// slhdsaParams builds NO_PREFIX SLH-DSA-SHA2-128s parameters or signals test failure.
func slhdsaParams(t *testing.T) key.Parameters {
	t.Helper()
	params, err := tinkslhdsa.NewParameters(tinkslhdsa.SHA2, 64, tinkslhdsa.SmallSignature, tinkslhdsa.VariantNoPrefix)
	if err != nil {
		t.Fatalf("tinkslhdsa.NewParameters(SHA2, 64, SmallSignature, VariantNoPrefix) err = %v, want nil", err)
	}
	return params
}

// newPQCTestKey generates a real post-quantum key pair with Tink, returning the raw public key bytes
// (as KMS serves them in NIST_PQC form) and a signer producing raw signatures over a message.
func newPQCTestKey(t *testing.T, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, params key.Parameters, nistPQCOnly bool) pqcTestKey {
	t.Helper()
	manager := keyset.NewManager()
	keyID, err := manager.AddNewKeyFromParameters(params)
	if err != nil {
		t.Fatalf("manager.AddNewKeyFromParameters(%v) err = %v, want nil", params, err)
	}
	if err := manager.SetPrimary(keyID); err != nil {
		t.Fatalf("manager.SetPrimary(%v) err = %v, want nil", keyID, err)
	}
	handle, err := manager.Handle()
	if err != nil {
		t.Fatalf("manager.Handle() err = %v, want nil", err)
	}
	signer, err := signature.NewSigner(handle)
	if err != nil {
		t.Fatalf("signature.NewSigner(handle) err = %v, want nil", err)
	}
	publicHandle, err := handle.Public()
	if err != nil {
		t.Fatalf("handle.Public() err = %v, want nil", err)
	}
	entry, err := publicHandle.Primary()
	if err != nil {
		t.Fatalf("publicHandle.Primary() err = %v, want nil", err)
	}
	var rawPublicKey []byte
	switch publicKey := entry.Key().(type) {
	case *tinkmldsa.PublicKey:
		rawPublicKey = publicKey.KeyBytes()
	case *tinkslhdsa.PublicKey:
		rawPublicKey = publicKey.KeyBytes()
	default:
		t.Fatalf("unexpected public key type %T", publicKey)
	}
	return pqcTestKey{
		algorithm:    algorithm,
		rawPublicKey: rawPublicKey,
		nistPQCOnly:  nistPQCOnly,
		sign: func(t *testing.T, message []byte) []byte {
			t.Helper()
			signature, err := signer.Sign(message)
			if err != nil {
				t.Fatalf("signer.Sign() err = %v, want nil", err)
			}
			return signature
		},
	}
}

// generateRSA generates an RSA private key of the given size or signals test failure.
func generateRSA(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(rand.Reader, %d) err = %v, want nil", bits, err)
	}
	return key
}

// pkixPEM encodes a public key as PEM-wrapped PKIX (SubjectPublicKeyInfo), matching the format
// GCP KMS returns for classical algorithms.
func pkixPEM(t *testing.T, publicKey crypto.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey(%v) err = %v, want nil", publicKey, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// digestOf returns the hash of message.
func digestOf(hash crypto.Hash, message []byte) []byte {
	h := hash.New()
	h.Write(message)
	return h.Sum(nil)
}

func newECDSATestKey(t *testing.T, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, curve elliptic.Curve, hash crypto.Hash) classicalTestKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(%v, rand.Reader) err = %v, want nil", curve, err)
	}
	return classicalTestKey{
		algorithm:    algorithm,
		pemPublicKey: pkixPEM(t, priv.Public()),
		sign: func(t *testing.T, message []byte) []byte {
			t.Helper()
			// KMS returns DER-encoded ECDSA signatures over the digest.
			signature, err := ecdsa.SignASN1(rand.Reader, priv, digestOf(hash, message))
			if err != nil {
				t.Fatalf("ecdsa.SignASN1(rand.Reader, priv, digest) err = %v, want nil", err)
			}
			return signature
		},
	}
}

func newRSAPKCS1TestKey(t *testing.T, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, priv *rsa.PrivateKey, hash crypto.Hash) classicalTestKey {
	t.Helper()
	return classicalTestKey{
		algorithm:    algorithm,
		pemPublicKey: pkixPEM(t, priv.Public()),
		sign: func(t *testing.T, message []byte) []byte {
			t.Helper()
			signature, err := rsa.SignPKCS1v15(rand.Reader, priv, hash, digestOf(hash, message))
			if err != nil {
				t.Fatalf("rsa.SignPKCS1v15(rand.Reader, priv, %v, digest) err = %v, want nil", hash, err)
			}
			return signature
		},
	}
}

func newRSAPSSTestKey(t *testing.T, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, priv *rsa.PrivateKey, hash crypto.Hash) classicalTestKey {
	t.Helper()
	return classicalTestKey{
		algorithm:    algorithm,
		pemPublicKey: pkixPEM(t, priv.Public()),
		sign: func(t *testing.T, message []byte) []byte {
			t.Helper()
			// KMS uses a salt length equal to the hash length.
			signature, err := rsa.SignPSS(rand.Reader, priv, hash, digestOf(hash, message), &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hash,
			})
			if err != nil {
				t.Fatalf("rsa.SignPSS(rand.Reader, priv, %v, digest) err = %v, want nil", hash, err)
			}
			return signature
		},
	}
}

func TestGRPCVerifier_Success(t *testing.T) {
	for keyName, testKey := range getVerifierClassicalKeys(t) {
		t.Run(testKey.algorithm.String(), func(t *testing.T) {
			mockServer := &mockKMS{}
			gcpKMSClient := setupMockKMSClient(t.Context(), t, mockServer)

			verifier, err := NewGRPCVerifier(t.Context(), keyName, gcpKMSClient)
			if err != nil {
				t.Fatalf("NewGRPCVerifier(%q) err = %v, want nil", keyName, err)
			}
			// Classical algorithms are fully served by the PEM response; NIST_PQC is never requested.
			wantFormats := []kmspb.PublicKey_PublicKeyFormat{kmspb.PublicKey_PEM}
			if !cmp.Equal(mockServer.getPublicKeyFormatRequests, wantFormats) {
				t.Errorf("GetPublicKey requests = %v, want %v", mockServer.getPublicKeyFormatRequests, wantFormats)
			}

			assertVerifyRoundTrip(t, verifier, testKey.sign)
		})
	}
}

func TestGRPCVerifier_PQCSuccess(t *testing.T) {
	for keyName, testKey := range getVerifierPQCKeys(t) {
		t.Run(testKey.algorithm.String(), func(t *testing.T) {
			mockServer := &mockKMS{}
			gcpKMSClient := setupMockKMSClient(t.Context(), t, mockServer)

			verifier, err := NewGRPCVerifier(t.Context(), keyName, gcpKMSClient)
			if err != nil {
				t.Fatalf("NewGRPCVerifier(%q) err = %v, want nil", keyName, err)
			}
			// Post-quantum keys are served as raw bytes: PEM is attempted first, then NIST_PQC is fetched.
			wantFormats := []kmspb.PublicKey_PublicKeyFormat{kmspb.PublicKey_PEM, kmspb.PublicKey_NIST_PQC}
			if !cmp.Equal(mockServer.getPublicKeyFormatRequests, wantFormats) {
				t.Errorf("GetPublicKey requests = %v, want %v", mockServer.getPublicKeyFormatRequests, wantFormats)
			}

			assertVerifyRoundTrip(t, verifier, testKey.sign)
		})
	}
}

// assertVerifyRoundTrip checks that verifier accepts a valid signature over verifyMessage and rejects
// both a wrong message and a corrupted signature.
func assertVerifyRoundTrip(t *testing.T, verifier *GRPCVerifier, sign func(t *testing.T, message []byte) []byte) {
	t.Helper()
	signature := sign(t, verifyMessage)
	if err := verifier.Verify(signature, verifyMessage); err != nil {
		t.Errorf("verifier.Verify() err = %v, want nil", err)
	}
	if err := verifier.Verify(signature, []byte("wrong data")); err == nil {
		t.Errorf("verifier.Verify(signature, wrongData) err = nil, want error")
	}
	corrupted := bytes.Clone(signature)
	corrupted[len(corrupted)-1] ^= 0xFF
	if err := verifier.Verify(corrupted, verifyMessage); err == nil {
		t.Errorf("verifier.Verify(corruptedSignature, data) err = nil, want error")
	}
}

func TestGRPCVerifier_FromPublicKeySuccess(t *testing.T) {
	for _, testKey := range getVerifierClassicalKeys(t) {
		t.Run(testKey.algorithm.String(), func(t *testing.T) {
			verifier, err := NewGRPCVerifierFromPublicKey(testKey.pemPublicKey, testKey.algorithm)
			if err != nil {
				t.Fatalf("NewGRPCVerifierFromPublicKey(%v) err = %v, want nil", testKey.algorithm, err)
			}
			assertVerifyRoundTrip(t, verifier, testKey.sign)
		})
	}
}

func TestGRPCVerifier_FromPublicKeyPQCSuccess(t *testing.T) {
	for _, testKey := range getVerifierPQCKeys(t) {
		t.Run(testKey.algorithm.String(), func(t *testing.T) {
			verifier, err := NewGRPCVerifierFromPublicKey(testKey.rawPublicKey, testKey.algorithm)
			if err != nil {
				t.Fatalf("NewGRPCVerifierFromPublicKey(%v) err = %v, want nil", testKey.algorithm, err)
			}
			assertVerifyRoundTrip(t, verifier, testKey.sign)
		})
	}
}

func TestGRPCVerifier_PQCMismatchedAlgorithmVerifyFails(t *testing.T) {
	pqcKeys := getVerifierPQCKeys(t)
	verifier44, err := NewGRPCVerifierFromPublicKey(pqcKeys[verifyKeyNameMLDSA44].rawPublicKey, kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44)
	if err != nil {
		t.Fatalf("NewGRPCVerifierFromPublicKey(ML_DSA_44) err = %v, want nil", err)
	}
	verifier65, err := NewGRPCVerifierFromPublicKey(pqcKeys[verifyKeyNameMLDSA65].rawPublicKey, kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65)
	if err != nil {
		t.Fatalf("NewGRPCVerifierFromPublicKey(ML_DSA_65) err = %v, want nil", err)
	}

	sig65 := pqcKeys[verifyKeyNameMLDSA65].sign(t, verifyMessage)
	if err := verifier44.Verify(sig65, verifyMessage); err == nil {
		t.Errorf("verifier44.Verify(sig65, verifyMessage) err = nil, want error")
	}

	sig44 := pqcKeys[verifyKeyNameMLDSA44].sign(t, verifyMessage)
	if err := verifier65.Verify(sig44, verifyMessage); err == nil {
		t.Errorf("verifier65.Verify(sig44, verifyMessage) err = nil, want error")
	}
}

func TestNewGRPCVerifier_NilKMSClientFails(t *testing.T) {
	_, err := NewGRPCVerifier(t.Context(), verifyKeyNameECP256, nil)
	if err == nil {
		t.Errorf("NewGRPCVerifier(_, nil) succeeded, want error")
	}
}

func TestNewGRPCVerifier_Fails(t *testing.T) {
	// Populate verifierClassicalKeys to facilitate lookup within mockKMS.
	_ = getVerifierClassicalKeys(t)
	_ = getVerifierPQCKeys(t)
	testcases := []struct {
		name    string
		keyName string
		wantErr string
	}{
		{
			name:    "empty key name",
			keyName: "",
			wantErr: "does not match",
		},
		{
			name:    "malformed key name",
			keyName: "Wrong/Key/Name",
			wantErr: "does not match",
		},
		{
			name:    "get public key fails",
			keyName: verifyKeyNameErrorGetPublicKey,
			wantErr: "GCP KMS GetPublicKey failed",
		},
		{
			name:    "checksum mismatch",
			keyName: verifyKeyNameErrorChecksumMismatch,
			wantErr: "checksum verification failed",
		},
		{
			name:    "wrong key name in response",
			keyName: verifyKeyNameErrorWrongKeyName,
			wantErr: "does not match the requested key name",
		},
		{
			name:    "unsupported algorithm",
			keyName: verifyKeyNameErrorUnsupportedAlgorithm,
			wantErr: "is not supported",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			mockServer := &mockKMS{}
			gcpKMSClient := setupMockKMSClient(t.Context(), t, mockServer)

			_, err := NewGRPCVerifier(t.Context(), tc.keyName, gcpKMSClient)
			if err == nil {
				t.Fatalf("NewGRPCVerifier(%q) succeeded, want error", tc.keyName)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("NewGRPCVerifier(%q) error = %v, want substring %q", tc.keyName, err, tc.wantErr)
			}
		})
	}
}

func TestNewGRPCVerifierFromPublicKey_Fails(t *testing.T) {
	classicalKeys := getVerifierClassicalKeys(t)
	pqcKeys := getVerifierPQCKeys(t)
	ecKey := classicalKeys[verifyKeyNameECP256]
	rsaKey := classicalKeys[verifyKeyNameRSAPKCS12048]
	mldsaKey := pqcKeys[verifyKeyNameMLDSA44]
	testcases := []struct {
		name      string
		publicKey []byte
		algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		wantErr   string
	}{
		{
			name:      "empty public key",
			publicKey: nil,
			algorithm: ecKey.algorithm,
			wantErr:   "public key is empty",
		},
		{
			name:      "unspecified algorithm",
			publicKey: ecKey.pemPublicKey,
			algorithm: kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED,
			wantErr:   "is not supported",
		},
		{
			name:      "malformed pem",
			publicKey: []byte("not a valid pem"),
			algorithm: ecKey.algorithm,
			wantErr:   "failed to decode PEM",
		},
		{
			name:      "rsa bytes with ecdsa algorithm",
			publicKey: rsaKey.pemPublicKey,
			algorithm: ecKey.algorithm,
			wantErr:   "not an ECDSA key",
		},
		{
			name:      "ecdsa bytes with rsa algorithm",
			publicKey: ecKey.pemPublicKey,
			algorithm: rsaKey.algorithm,
			wantErr:   "not an RSA key",
		},
		{
			name:      "modulus size mismatch",
			publicKey: rsaKey.pemPublicKey,
			algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
			wantErr:   "modulus",
		},
		{
			name:      "mldsa key length mismatch",
			publicKey: mldsaKey.rawPublicKey,
			algorithm: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65,
			wantErr:   "public key length",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewGRPCVerifierFromPublicKey(tc.publicKey, tc.algorithm)
			if err == nil {
				t.Fatalf("NewGRPCVerifierFromPublicKey(%v) succeeded, want error", tc.algorithm)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("NewGRPCVerifierFromPublicKey(%v) error = %v, want substring %q", tc.algorithm, err, tc.wantErr)
			}
		})
	}
}
