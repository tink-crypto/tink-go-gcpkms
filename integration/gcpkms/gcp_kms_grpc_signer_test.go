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
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	signKeyNamePQCAlgorithm                         = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/11"
	signKeyNameErrorWrongKeyNameGetPublicKey        = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/12"
	signKeyNamePQCAlgorithmSupportsPem              = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/13"
	signKeyNameErrorChecksumMismatchGetPublicKeyPQC = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/14"
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
	if keyName == signKeyNamePQCAlgorithm || keyName == signKeyNamePQCAlgorithmSupportsPem {
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

func (s *mockKMS) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	s.getPublicKeyFormatRequests = append(s.getPublicKeyFormatRequests, req.GetPublicKeyFormat())
	response := &kmspb.PublicKey{}
	response.Name = req.GetName()
	response.ProtectionLevel = kmspb.ProtectionLevel_SOFTWARE // Default protection level.
	response.PublicKeyFormat = req.GetPublicKeyFormat()

	publicKeyData := []byte("pem")
	publicKeyCrc32c := computeChecksum(publicKeyData)
	response.PublicKey = &kmspb.ChecksummedData{
		Data:           publicKeyData,
		Crc32CChecksum: &wrappb.Int64Value{Value: publicKeyCrc32c},
	}

	switch req.GetName() {
	case signKeyNameRequiresData1:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case signKeyNameRequiresData2:
		response.ProtectionLevel = kmspb.ProtectionLevel_EXTERNAL
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256
		return response, nil
	case signKeyNameRequiresDigest:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256
		return response, nil
	case signKeyNameErrorGetPublicKey:
		return nil, status.Error(codes.Internal, "Internal error")
	case signKeyNameErrorAsymmetricSign:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case signKeyNameErrorCRC32C:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case signKeyNameErrorCRC32CNotVerified:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case signKeyNameErrorWrongKeyName:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case signKeyNameErrorUnsupportedAlgorithm:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256
		return response, nil
	case signKeyNameErrorChecksumMismatchGetPublicKey:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		response.PublicKey.Crc32CChecksum.Value = 1
		return response, nil
	case signKeyNamePQCAlgorithm:
		if req.GetPublicKeyFormat() != kmspb.PublicKey_NIST_PQC {
			return nil, status.Error(codes.InvalidArgument, "Only NIST_PQC format is supported for PQC algorithms.")
		}
		response.Algorithm = kmspb.CryptoKeyVersion_PQ_SIGN_SLH_DSA_SHA2_128S
		response.PublicKeyFormat = kmspb.PublicKey_NIST_PQC
		publicKeyData := []byte("pqc")
		publicKeyCrc32c := computeChecksum(publicKeyData)
		response.PublicKey = &kmspb.ChecksummedData{
			Data:           publicKeyData,
			Crc32CChecksum: &wrappb.Int64Value{Value: publicKeyCrc32c},
		}
		return response, nil
	case signKeyNameErrorWrongKeyNameGetPublicKey:
		response.Name = "wrong key name"
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case signKeyNamePQCAlgorithmSupportsPem:
		response.Algorithm = kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65
		response.PublicKeyFormat = kmspb.PublicKey_PEM
		publicKeyData := []byte("pqc")
		publicKeyCrc32c := computeChecksum(publicKeyData)
		response.PublicKey = &kmspb.ChecksummedData{
			Data:           publicKeyData,
			Crc32CChecksum: &wrappb.Int64Value{Value: publicKeyCrc32c},
		}
		return response, nil
	case signKeyNameErrorChecksumMismatchGetPublicKeyPQC:
		if req.GetPublicKeyFormat() != kmspb.PublicKey_NIST_PQC {
			return nil, status.Error(codes.InvalidArgument, "Only NIST_PQC format is supported for PQC algorithms.")
		}
		response.Algorithm = kmspb.CryptoKeyVersion_PQ_SIGN_SLH_DSA_SHA2_128S
		response.PublicKeyFormat = kmspb.PublicKey_NIST_PQC
		response.PublicKey.Crc32CChecksum.Value = 1
		return response, nil
	default:
		return nil, status.Error(codes.NotFound, "Key not found")
	}
}

func (s *mockKMS) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	s.lastAsymmetricSignRequest = req
	if req.GetName() == signKeyNameErrorAsymmetricSign {
		return nil, status.Error(codes.Internal, "Internal error")
	}
	response := &kmspb.AsymmetricSignResponse{
		Name: req.GetName(),
	}
	if req.GetDigest() != nil {
		response.VerifiedDigestCrc32C = true
		response.Signature = signatureForKey([]byte(signDigest), req.GetName())
	} else {
		response.VerifiedDataCrc32C = true
		response.Signature = signatureForKey(req.GetData(), req.GetName())
	}
	response.SignatureCrc32C = &wrappb.Int64Value{Value: computeChecksum(response.GetSignature())}
	switch req.GetName() {
	case signKeyNameErrorWrongKeyName:
		response.Name = "wrong key name"
	case signKeyNameErrorCRC32C:
		response.SignatureCrc32C = &wrappb.Int64Value{Value: 1}
	case signKeyNameErrorCRC32CNotVerified:
		response.VerifiedDataCrc32C = false
		response.VerifiedDigestCrc32C = false
	}
	return response, nil
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
	// Digest-mode algorithms sign the SHA-256 digest of the data.
	digestOfData := sha256.Sum256([]byte(signData))
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
			name:          "sign digest success",
			keyName:       signKeyNameRequiresDigest,
			dataToSign:    []byte(signData),
			wantSignature: expectedSignature([]byte(signDigest)),
			wantRequest: &kmspb.AsymmetricSignRequest{
				Name:         signKeyNameRequiresDigest,
				Digest:       &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digestOfData[:]}},
				DigestCrc32C: &wrappb.Int64Value{Value: computeChecksum(digestOfData[:])},
			},
			wantPublicKeyFormats: pemOnly,
		},
		{
			name:                 "sign pqc algorithm success",
			keyName:              signKeyNamePQCAlgorithm,
			dataToSign:           []byte(signData),
			wantSignature:        expectedPQCSignature([]byte(signData)),
			wantRequest:          dataSignRequest(signKeyNamePQCAlgorithm, []byte(signData)),
			wantPublicKeyFormats: pemThenNISTPQC,
		},
		{
			name:                 "sign pqc algorithm supports pem",
			keyName:              signKeyNamePQCAlgorithmSupportsPem,
			dataToSign:           []byte(signData),
			wantSignature:        expectedPQCSignature([]byte(signData)),
			wantRequest:          dataSignRequest(signKeyNamePQCAlgorithmSupportsPem, []byte(signData)),
			wantPublicKeyFormats: pemOnly,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			mockServer := &mockKMS{}
			signer := initializeSigner(t, mockServer, tc.keyName)

			if !cmp.Equal(mockServer.getPublicKeyFormatRequests, tc.wantPublicKeyFormats) {
				t.Errorf("GetPublicKey requests for %q had format requests = %v, want %v", tc.keyName, mockServer.getPublicKeyFormatRequests, tc.wantPublicKeyFormats)
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
