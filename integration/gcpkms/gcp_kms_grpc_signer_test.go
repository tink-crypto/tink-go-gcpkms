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
	"net"
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	// Placeholder for internal proto import.
	kmspbgrpc "google.golang.org/genproto/googleapis/cloud/kms/v1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	wrappb "google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	Data                             = "data for signing"
	Digest                           = "digest for signing"
	KeyNameRequiresData1             = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/1"
	KeyNameRequiresData2             = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/2"
	KeyNameRequiresDigest            = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/3"
	KeyNameErrorGetPublicKey         = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/4"
	KeyNameErrorAsymmetricSign       = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/5"
	KeyNameErrorCrc32cNotVerified    = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/7"
	KeyNameErrorWrongKeyName         = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/8"
	KeyNameErrorUnsupportedAlgorithm = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/9"
)

type mockKMS struct {
	kmspbgrpc.UnimplementedKeyManagementServiceServer
}

func ExpectSign(data []byte) []byte {
	return []byte("signature for " + string(data))
}

func Sign(data []byte, keyName string) []byte {
	return []byte("signature for " + string(data))
}

func (s *mockKMS) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
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
	case KeyNameRequiresData1:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case KeyNameRequiresData2:
		response.ProtectionLevel = kmspb.ProtectionLevel_EXTERNAL
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256
		return response, nil
	case KeyNameRequiresDigest:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256
		return response, nil
	case KeyNameErrorGetPublicKey:
		return nil, status.Error(codes.Internal, "Internal error")
	case KeyNameErrorAsymmetricSign:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case KeyNameErrorCrc32cNotVerified:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case KeyNameErrorWrongKeyName:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case KeyNameErrorUnsupportedAlgorithm:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256
		return response, nil
	default:
		return nil, status.Errorf(codes.NotFound, "Key not found")
	}
}

func (s *mockKMS) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	if req.GetName() == KeyNameErrorAsymmetricSign {
		return nil, status.Errorf(codes.Internal, "Internal error")
	}
	response := &kmspb.AsymmetricSignResponse{
		Name: req.GetName(),
	}
	if req.GetDigest() != nil {
		response.VerifiedDigestCrc32C = true
		response.Signature = Sign([]byte(Digest), req.GetName())
	} else {
		response.VerifiedDataCrc32C = true
		response.Signature = Sign(req.GetData(), req.GetName())
	}
	response.SignatureCrc32C = &wrappb.Int64Value{Value: computeChecksum(response.GetSignature())}
	switch req.GetName() {
	case KeyNameErrorWrongKeyName:
		response.Name = "wrong key name"
	case KeyNameErrorCrc32cNotVerified:
		response.VerifiedDataCrc32C = false
		response.VerifiedDigestCrc32C = false
	}
	return response, nil
}

func setupMockKMSClient(t *testing.T, mockServer *mockKMS) *kms.KeyManagementClient {
	t.Helper()

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()

	kmspbgrpc.RegisterKeyManagementServiceServer(s, mockServer)

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Logf("Mock gRPC server exited with error: %v", err)
		}
	}()

	t.Cleanup(func() {
		s.Stop()
		lis.Close()
	})

	dialer := func(ctx context.Context, address string) (net.Conn, error) {
		return lis.Dial()
	}
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	gcpKMSClient, err := kms.NewKeyManagementClient(t.Context(), option.WithGRPCConn(conn))
	if err != nil {
		t.Fatalf("kms.NewKeyManagementClient with GRPCConn failed: %v", err)
	}
	return gcpKMSClient
}

func initializeSigner(t *testing.T, mockServer *mockKMS, keyName string) *GRPCSigner {
	t.Helper()
	gcpKMSClient := setupMockKMSClient(t, mockServer)
	signer, err := NewGRPCSigner(t.Context(), keyName, gcpKMSClient)
	if err != nil {
		t.Fatalf("NewGRPCSigner failed: %v", err)
	}
	return signer
}

func TestNewGRPCSigner_NilKmsClientFails(t *testing.T) {
	_, err := NewGRPCSigner(t.Context(), KeyNameRequiresData1, nil)
	if err == nil {
		t.Errorf("NewGRPCSigner succeeded, want error")
	}
}

func TestNewGRPCSigner_Fails(t *testing.T) {
	type testCase struct {
		name    string
		keyName string
		wantErr string
	}
	testcases := []testCase{
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
			keyName: KeyNameErrorGetPublicKey,
			wantErr: "GCP KMS GetPublicKey failed",
		},
		{
			name:    "unsupported algorithm",
			keyName: KeyNameErrorUnsupportedAlgorithm,
			wantErr: "is not supported",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			mockServer := &mockKMS{}
			gcpKMSClient := setupMockKMSClient(t, mockServer)

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
	type testCase struct {
		name       string
		keyName    string
		dataToSign []byte
		wantErr    string
	}
	testcases := []testCase{
		{
			name:       "asymmetric sign fails",
			keyName:    KeyNameErrorAsymmetricSign,
			dataToSign: []byte(Data),
			wantErr:    "GCP KMS AsymmetricSign failed",
		},
		{
			name:       "input checksum fails",
			keyName:    KeyNameErrorCrc32cNotVerified,
			dataToSign: []byte(Data),
			wantErr:    "checking the input checksum failed",
		},
		{
			name:       "oversized input data",
			keyName:    KeyNameRequiresData1,
			dataToSign: bytes.Repeat([]byte("A"), 64*1024+1),
			wantErr:    "is larger than",
		},
		{
			name:       "mismatched key name in response",
			keyName:    KeyNameErrorWrongKeyName,
			dataToSign: []byte(Data),
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
	type testCase struct {
		name          string
		keyName       string
		dataToSign    []byte
		wantSignature []byte
	}
	testcases := []testCase{
		{
			name:          "sign data on algorithm success",
			keyName:       KeyNameRequiresData1,
			dataToSign:    []byte(Data),
			wantSignature: ExpectSign([]byte(Data)),
		},
		{
			name:          "sign data on protection level success",
			keyName:       KeyNameRequiresData2,
			dataToSign:    []byte(Data),
			wantSignature: ExpectSign([]byte(Data)),
		},
		{
			name:          "sign digest success",
			keyName:       KeyNameRequiresDigest,
			dataToSign:    []byte(Data),
			wantSignature: ExpectSign([]byte(Digest)),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			mockServer := &mockKMS{}
			signer := initializeSigner(t, mockServer, tc.keyName)

			gotSignature, err := signer.SignWithContext(t.Context(), tc.dataToSign)
			if err != nil {
				t.Errorf("signer.SignWithContext(%q) error = %v, want nil", string(tc.dataToSign), err)
			}
			if !bytes.Equal(gotSignature, tc.wantSignature) {
				t.Errorf("signer.SignWithContext(%q) = %v, want %v", string(tc.dataToSign), string(gotSignature), string(tc.wantSignature))
			}

		})
	}
}
