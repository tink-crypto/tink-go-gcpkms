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
	"bytes"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"

	// Placeholder for internal proto import.
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	wrappb "google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	signData                                        = "data for signing"
	signDigest                                      = "digest for signing"
	signKeyNameRequiresData1                        = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/1"
	signKeyNameRequiresData2                        = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/2"
	signKeyNameRequiresDigest                       = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/3"
	signKeyNameErrorGetPublicKey                    = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/4"
	signKeyNameErrorAsymmetricSign                  = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/5"
	signKeyNameErrorCRC32C                          = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/6"
	signKeyNameErrorCRC32CNotVerified               = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/7"
	signKeyNameErrorWrongKeyName                    = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/8"
	signKeyNameErrorUnsupportedAlgorithm            = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/9"
	signKeyNameErrorChecksumMismatchGetPublicKey    = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/10"
	signKeyNameErrorWrongKeyNameGetPublicKey        = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/11"
	signKeyNameErrorChecksumMismatchGetPublicKeyPQC = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/12"
	signKeyNameMLDSA44                              = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/13"
	signKeyNameMLDSA65                              = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/14"
	signKeyNameMLDSA87                              = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/15"
	signKeyNamePureSLHDSA                           = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/16"
	signKeyNameHashSLHDSA                           = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/17"
	signKeyNameMLDSA44ExternalMu                    = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/18"
	signKeyNameMLDSA65ExternalMu                    = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/19"
	signKeyNameMLDSA87ExternalMu                    = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/20"
	signKeyNameMLDSAExternalMuInvalidKey            = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/21"
)

// expectedSignature returns the expected signature bytes for non-PQC algorithms.
func expectedSignature(data []byte) []byte {
	return []byte("signature for " + string(data))
}

// expectedPQCSignature returns the expected signature bytes for PQC algorithms.
func expectedPQCSignature(data []byte) []byte {
	return []byte("pqc signature for " + string(data))
}

// signatureForKey returns the expected signature bytes based on the key name.
func signatureForKey(data []byte, keyName string) []byte {
	switch keyName {
	case signKeyNamePureSLHDSA, signKeyNameMLDSA44,
		signKeyNameMLDSA65, signKeyNameMLDSA87, signKeyNameHashSLHDSA,
		signKeyNameMLDSA44ExternalMu, signKeyNameMLDSA65ExternalMu, signKeyNameMLDSA87ExternalMu:

		return []byte("pqc signature for " + string(data))
	}
	return []byte("signature for " + string(data))
}

// dataSignRequest returns the AsymmetricSignRequest that the signer is expected
// to send for algorithms that sign the raw data.
func dataSignRequest(keyName string, data []byte) *kmspb.AsymmetricSignRequest {
	return &kmspb.AsymmetricSignRequest{
		Name:       keyName,
		Data:       data,
		DataCrc32C: &wrappb.Int64Value{Value: computeChecksum(data)},
	}
}

// sha256DigestSignRequest returns the AsymmetricSignRequest that the signer is
// expected to send for algorithms that sign the SHA-256 digest of the data.
func sha256DigestSignRequest(keyName string, data []byte) *kmspb.AsymmetricSignRequest {
	digest := sha256.Sum256(data)
	return &kmspb.AsymmetricSignRequest{
		Name:         keyName,
		Digest:       &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest[:]}},
		DigestCrc32C: &wrappb.Int64Value{Value: computeChecksum(digest[:])},
	}
}

// mldsaTestPublicKey returns deterministic bytes of the given size to stand in
// for an encoded ML-DSA public key. The signer only checks the length and hashes
// the bytes, so a real key is unnecessary.
func mldsaTestPublicKey(size int) []byte {
	key := make([]byte, size)
	for i := range key {
		key[i] = byte(i % 251)
	}
	return key
}

// externalMuSignRequest returns the AsymmetricSignRequest that the signer is
// expected to send for external-mu ML-DSA algorithms, which sign the SHAKE-256
// message representative (μ) of the data.
func externalMuSignRequest(keyName string, publicKeyBytes, data []byte) *kmspb.AsymmetricSignRequest {
	tr := sha3.SumSHAKE256(publicKeyBytes, mldsaPublicKeyHashBytes)
	mu := computeMLDSAExternalMu(tr, data)
	return &kmspb.AsymmetricSignRequest{
		Name:         keyName,
		Digest:       &kmspb.Digest{Digest: &kmspb.Digest_ExternalMu{ExternalMu: mu}},
		DigestCrc32C: &wrappb.Int64Value{Value: computeChecksum(mu)},
	}
}

// initializeSigner sets up a mock KMS client and returns a new GRPCSigner for testing.
func initializeSigner(t *testing.T, mockServer *mockKMS, keyName string) *GRPCSigner {
	t.Helper()
	gcpKMSClient := setupMockKMSClient(t.Context(), t, mockServer)
	signer, err := NewGRPCSigner(t.Context(), keyName, gcpKMSClient)
	if err != nil {
		t.Fatalf("NewGRPCSigner failed: %v", err)
	}
	return signer
}

func TestNewGRPCSigner_NilKMSClientFails(t *testing.T) {
	_, err := NewGRPCSigner(t.Context(), signKeyNameRequiresData1, nil)
	if err == nil {
		t.Errorf("NewGRPCSigner(_, nil) succeeded, want error")
	}
}

func TestNewGRPCSigner_Fails(t *testing.T) {
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
			keyName: signKeyNameErrorGetPublicKey,
			wantErr: "GCP KMS GetPublicKey failed",
		},
		{
			name:    "unsupported algorithm",
			keyName: signKeyNameErrorUnsupportedAlgorithm,
			wantErr: "is not supported",
		},
		{
			name:    "checksum mismatch get public key",
			keyName: signKeyNameErrorChecksumMismatchGetPublicKey,
			wantErr: "checksum verification failed",
		},
		{
			name:    "checksum mismatch get public key pqc",
			keyName: signKeyNameErrorChecksumMismatchGetPublicKeyPQC,
			wantErr: "checksum verification failed",
		},
		{
			name:    "wrong key name get public key",
			keyName: signKeyNameErrorWrongKeyNameGetPublicKey,
			wantErr: "does not match the requested key name",
		},
		{
			name:    "ml-dsa external-mu invalid key size",
			keyName: signKeyNameMLDSAExternalMuInvalidKey,
			wantErr: "incorrect public key size",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			mockServer := &mockKMS{}
			gcpKMSClient := setupMockKMSClient(t.Context(), t, mockServer)

			_, err := NewGRPCSigner(t.Context(), tc.keyName, gcpKMSClient)
			if err == nil {
				t.Errorf("NewGRPCSigner(%q) succeeded, want error", tc.keyName)
			}
			if err != nil && !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("NewGRPCSigner(%q) error = %v, want substring %q", tc.keyName, err, tc.wantErr)
			}
		})
	}
}

func TestGRPCSigner_SignWithContextFails(t *testing.T) {
	testcases := []struct {
		name       string
		keyName    string
		dataToSign []byte
		wantErr    string
	}{
		{
			name:       "asymmetric sign fails",
			keyName:    signKeyNameErrorAsymmetricSign,
			dataToSign: []byte(signData),
			wantErr:    "GCP KMS AsymmetricSign failed",
		},
		{
			name:       "input checksum fails",
			keyName:    signKeyNameErrorCRC32CNotVerified,
			dataToSign: []byte(signData),
			wantErr:    "checking the input checksum failed",
		},
		{
			name:       "signature checksum mismatch",
			keyName:    signKeyNameErrorCRC32C,
			dataToSign: []byte(signData),
			wantErr:    "signature checksum mismatch",
		},
		{
			name:       "oversized input data",
			keyName:    signKeyNameRequiresData1,
			dataToSign: bytes.Repeat([]byte("A"), 64*1024+1),
			wantErr:    "is larger than",
		},
		{
			name:       "mismatched key name in response",
			keyName:    signKeyNameErrorWrongKeyName,
			dataToSign: []byte(signData),
			wantErr:    "does not match the requested key name",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			mockServer := &mockKMS{}
			signer := initializeSigner(t, mockServer, tc.keyName)

			_, err := signer.SignWithContext(t.Context(), tc.dataToSign)
			if err == nil {
				t.Errorf("signer.SignWithContext(%q) succeeded, want error", tc.dataToSign)
			}
			if err != nil && !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("signer.SignWithContext(%q) error = %v, want substring %q", tc.dataToSign, err, tc.wantErr)
			}
		})
	}
}

func TestGRPCSigner_SignWithContextSuccess(t *testing.T) {
	pemOnly := []kmspb.PublicKey_PublicKeyFormat{kmspb.PublicKey_PEM}
	pemThenNISTPQC := []kmspb.PublicKey_PublicKeyFormat{kmspb.PublicKey_PEM, kmspb.PublicKey_NIST_PQC}
	testcases := []struct {
		name                 string
		keyName              string
		dataToSign           []byte
		wantSignature        []byte
		wantRequest          *kmspb.AsymmetricSignRequest
		wantPublicKeyFormats []kmspb.PublicKey_PublicKeyFormat
	}{
		{
			name:                 "sign data on algorithm success",
			keyName:              signKeyNameRequiresData1,
			dataToSign:           []byte(signData),
			wantSignature:        expectedSignature([]byte(signData)),
			wantRequest:          dataSignRequest(signKeyNameRequiresData1, []byte(signData)),
			wantPublicKeyFormats: pemOnly,
		},
		{
			name:                 "sign data on protection level success",
			keyName:              signKeyNameRequiresData2,
			dataToSign:           []byte(signData),
			wantSignature:        expectedSignature([]byte(signData)),
			wantRequest:          dataSignRequest(signKeyNameRequiresData2, []byte(signData)),
			wantPublicKeyFormats: pemOnly,
		},
		{
			name:                 "sign digest success",
			keyName:              signKeyNameRequiresDigest,
			dataToSign:           []byte(signData),
			wantSignature:        expectedSignature([]byte(signDigest)),
			wantRequest:          sha256DigestSignRequest(signKeyNameRequiresDigest, []byte(signData)),
			wantPublicKeyFormats: pemOnly,
		},
		{
			name:                 "sign large data success for digest based algorithm",
			keyName:              signKeyNameRequiresDigest,
			dataToSign:           bytes.Repeat([]byte("A"), 64*1024+1),
			wantSignature:        expectedSignature([]byte(signDigest)),
			wantRequest:          sha256DigestSignRequest(signKeyNameRequiresDigest, bytes.Repeat([]byte("A"), 64*1024+1)),
			wantPublicKeyFormats: pemOnly,
		},
		{
			name:                 "sign ml-dsa-44 algorithm success",
			keyName:              signKeyNameMLDSA44,
			dataToSign:           []byte(signData),
			wantSignature:        expectedPQCSignature([]byte(signData)),
			wantRequest:          dataSignRequest(signKeyNameMLDSA44, []byte(signData)),
			wantPublicKeyFormats: pemOnly,
		},
		{
			name:                 "sign ml-dsa-65 algorithm success",
			keyName:              signKeyNameMLDSA65,
			dataToSign:           []byte(signData),
			wantSignature:        expectedPQCSignature([]byte(signData)),
			wantRequest:          dataSignRequest(signKeyNameMLDSA65, []byte(signData)),
			wantPublicKeyFormats: pemOnly,
		},
		{
			name:                 "sign ml-dsa-87 algorithm success",
			keyName:              signKeyNameMLDSA87,
			dataToSign:           []byte(signData),
			wantSignature:        expectedPQCSignature([]byte(signData)),
			wantRequest:          dataSignRequest(signKeyNameMLDSA87, []byte(signData)),
			wantPublicKeyFormats: pemOnly,
		},
		{
			name:                 "sign slh-dsa algorithm success",
			keyName:              signKeyNamePureSLHDSA,
			dataToSign:           []byte(signData),
			wantSignature:        expectedPQCSignature([]byte(signData)),
			wantRequest:          dataSignRequest(signKeyNamePureSLHDSA, []byte(signData)),
			wantPublicKeyFormats: pemThenNISTPQC,
		},
		{
			name:                 "sign hash-slh-dsa algorithm success",
			keyName:              signKeyNameHashSLHDSA,
			dataToSign:           []byte(signData),
			wantSignature:        expectedPQCSignature([]byte(signDigest)),
			wantRequest:          sha256DigestSignRequest(signKeyNameHashSLHDSA, []byte(signData)),
			wantPublicKeyFormats: pemThenNISTPQC,
		},
		{
			name:                 "sign ml-dsa-44 external-mu algorithm success",
			keyName:              signKeyNameMLDSA44ExternalMu,
			dataToSign:           []byte(signData),
			wantSignature:        expectedPQCSignature([]byte(signDigest)),
			wantRequest:          externalMuSignRequest(signKeyNameMLDSA44ExternalMu, mldsaTestPublicKey(mldsa44PublicKeyBytes), []byte(signData)),
			wantPublicKeyFormats: pemThenNISTPQC,
		},
		{
			name:                 "sign ml-dsa-65 external-mu algorithm success",
			keyName:              signKeyNameMLDSA65ExternalMu,
			dataToSign:           []byte(signData),
			wantSignature:        expectedPQCSignature([]byte(signDigest)),
			wantRequest:          externalMuSignRequest(signKeyNameMLDSA65ExternalMu, mldsaTestPublicKey(mldsa65PublicKeyBytes), []byte(signData)),
			wantPublicKeyFormats: pemThenNISTPQC,
		},
		{
			name:                 "sign ml-dsa-87 external-mu algorithm success",
			keyName:              signKeyNameMLDSA87ExternalMu,
			dataToSign:           []byte(signData),
			wantSignature:        expectedPQCSignature([]byte(signDigest)),
			wantRequest:          externalMuSignRequest(signKeyNameMLDSA87ExternalMu, mldsaTestPublicKey(mldsa87PublicKeyBytes), []byte(signData)),
			wantPublicKeyFormats: pemThenNISTPQC,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			mockServer := &mockKMS{}
			signer := initializeSigner(t, mockServer, tc.keyName)

			if !cmp.Equal(mockServer.getPublicKeyFormatRequests, tc.wantPublicKeyFormats) {
				t.Errorf("GetPublicKey requests for %q with formats = %v, want %v", tc.keyName, mockServer.getPublicKeyFormatRequests, tc.wantPublicKeyFormats)
			}

			gotSignature, err := signer.SignWithContext(t.Context(), tc.dataToSign)
			if err != nil {
				t.Errorf("signer.SignWithContext(%q) error = %v, want nil", tc.dataToSign, err)
			}
			if !bytes.Equal(gotSignature, tc.wantSignature) {
				t.Errorf("signer.SignWithContext(%q) = %q, want %q", tc.dataToSign, gotSignature, tc.wantSignature)
			}
			if diff := cmp.Diff(tc.wantRequest, mockServer.lastAsymmetricSignRequest, protocmp.Transform()); diff != "" {
				t.Errorf("AsymmetricSign request for %q mismatch (-want +got):\n%s", tc.keyName, diff)
			}
		})
	}

}

func mustHexDecode(t *testing.T, input string) []byte {
	t.Helper()
	result, err := hex.DecodeString(input)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) error = %v", input, err)
	}
	return result
}

func TestComputeMLDSAExternalMu(t *testing.T) {
	// Known-answer vectors for μ = SHAKE256(SHAKE256(pk, 64) || 0x00 || 0x00 || data, 64)
	// (FIPS-204 §6.2, empty context), where the vectors were computed independently with Python's
	// hashlib.shake_256 over pk = mlDsaTestPublicKey(pkSize) and data = signData.
	testcases := []struct {
		name      string
		algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		pkSize    int
		wantMu    []byte
	}{
		{
			name:      "ml-dsa-44",
			algorithm: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44_EXTERNAL_MU,
			pkSize:    mldsa44PublicKeyBytes,
			wantMu:    mustHexDecode(t, "4856f58825ea886142257740202561dd56c874fe50c7fa2644fcb76149544bffa1e8e35b5d34d3760078244ea348b08173fc6f6ca3ccfbb87e6d230cb6054130"),
		},
		{
			name:      "ml-dsa-65",
			algorithm: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU,
			pkSize:    mldsa65PublicKeyBytes,
			wantMu:    mustHexDecode(t, "8af79318b6d333d59890db6895be53bcfc663970a1fd4a228fdcc2fac916475ca4778038298e2f2661f9437d819756579a5a91f9a16c7475e0193e7068b99e51"),
		},
		{
			name:      "ml-dsa-87",
			algorithm: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87_EXTERNAL_MU,
			pkSize:    mldsa87PublicKeyBytes,
			wantMu:    mustHexDecode(t, "e6306d86c4ef1b8f03aa4a9c4c1c50bcbc580ac5209ecc714fc4a08b7b4265a75322712923d71c2fb203a85944e09b44f0e3c7d90d7b43ad6c3145466cd6a858"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			publicKey := &kmspb.PublicKey{
				Algorithm: tc.algorithm,
				PublicKey: &kmspb.ChecksummedData{Data: mldsaTestPublicKey(tc.pkSize)},
			}
			tr, err := computeMLDSAPublicKeyHash(publicKey)
			if err != nil {
				t.Fatalf("computeMLDSAPublicKeyHash(%v) error = %v, want nil", tc.algorithm, err)
			}
			gotMu := computeMLDSAExternalMu(tr, []byte(signData))
			if !bytes.Equal(gotMu, tc.wantMu) {
				t.Errorf("computeMLDSAExternalMu(tr, %q) = %x, want %x", signData, gotMu, tc.wantMu)
			}
		})
	}
}

func TestUseNISTPQCFormat(t *testing.T) {
	testCases := []struct {
		name     string
		response *kmspb.PublicKey
		err      error
		want     bool
	}{
		{
			name:     "error requiring NIST_PQC format",
			response: nil,
			err:      errors.New("Only NIST_PQC format is supported for PQC algorithms"),
			want:     true,
		},
		{
			name:     "unrelated error with external-mu response (must not return true)",
			response: &kmspb.PublicKey{Algorithm: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44_EXTERNAL_MU},
			err:      errors.New("unrelated KMS error"),
			want:     false,
		},
		{
			name:     "no error with external-mu response",
			response: &kmspb.PublicKey{Algorithm: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44_EXTERNAL_MU},
			err:      nil,
			want:     true,
		},
		{
			name:     "no error with regular ML-DSA response",
			response: &kmspb.PublicKey{Algorithm: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44},
			err:      nil,
			want:     false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := useNISTPQCFormat(tc.response, tc.err); got != tc.want {
				t.Errorf("useNISTPQCFormat() = %v, want %v", got, tc.want)
			}
		})
	}
}
