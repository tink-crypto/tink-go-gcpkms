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
	"hash/crc32"
	"net"
	"testing"

	kmspbgrpc "google.golang.org/genproto/googleapis/cloud/kms/v1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	"cloud.google.com/go/kms/apiv1"
	"google.golang.org/api/option"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

// mockKMSService is a mock implementation of the KeyManagementServiceServer.
type mockKMSService struct {
	kmspbgrpc.UnimplementedKeyManagementServiceServer
	encryptResponse *kmspb.EncryptResponse
	decryptResponse *kmspb.DecryptResponse
}

// Encrypt implements the server-side Encrypt RPC.
func (m *mockKMSService) Encrypt(ctx context.Context, in *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	return m.encryptResponse, nil
}

// Decrypt implements the server-side Decrypt RPC.
func (m *mockKMSService) Decrypt(ctx context.Context, in *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	return m.decryptResponse, nil
}

func initializeGRPCClientWithResponse(t *testing.T, encryptResponse *kmspb.EncryptResponse, decryptResponse *kmspb.DecryptResponse) *kms.KeyManagementClient {
	t.Helper()

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()

	mockService := &mockKMSService{
		encryptResponse: encryptResponse,
		decryptResponse: decryptResponse,
	}

	kmspbgrpc.RegisterKeyManagementServiceServer(s, mockService)

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
		t.Fatalf("failed to dial bufnet: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	gcpKMSClient, err := kms.NewKeyManagementClient(t.Context(), option.WithGRPCConn(conn))
	if err != nil {
		t.Fatalf("kms.NewKeyManagementClient with GRPCConn failed: %v", err)
	}

	return gcpKMSClient
}

func TestGRPCEncrypt_FailsWhenPlaintextUnverifed(t *testing.T) {
	additionalData := []byte("additional data")
	ciphertext := []byte("ciphertext")
	ciphertextCrc32c := int64(crc32.Checksum(ciphertext, crc32.MakeTable(crc32.Castagnoli)))

	testcases := []struct {
		name            string
		encryptResponse *kmspb.EncryptResponse
	}{
		{
			name: "verified_plaintext_crc32c is false",
			encryptResponse: &kmspb.EncryptResponse{
				Ciphertext:              ciphertext,
				CiphertextCrc32C:        wrapperspb.Int64(ciphertextCrc32c),
				VerifiedPlaintextCrc32C: false,
				VerifiedAdditionalAuthenticatedDataCrc32C: true,
			},
		},
		{
			name: "verified_plaintext_crc32c missing",
			encryptResponse: &kmspb.EncryptResponse{
				Ciphertext:       ciphertext,
				CiphertextCrc32C: wrapperspb.Int64(ciphertextCrc32c),
				VerifiedAdditionalAuthenticatedDataCrc32C: true,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			client := initializeGRPCClientWithResponse(t, tc.encryptResponse, nil)

			aead := newGRPCAEAD("key name", client)
			// Encryption should fail for all plaintexts (empty or non-empty).
			_, err := aead.EncryptWithContext(t.Context(), []byte("plaintext"), additionalData)
			if err == nil {
				t.Errorf("a.Encrypt err = nil, want error")
			}
			_, err = aead.EncryptWithContext(t.Context(), []byte(""), additionalData)
			if err == nil {
				t.Errorf("a.Encrypt err = nil, want error")
			}
		})
	}
}

func TestGRPCEncrypt_FailsWhenAdditionalAuthenticatedDataUnverifed(t *testing.T) {
	plaintext := []byte("plaintext")
	ciphertext := []byte("ciphertext")
	ciphertextCrc32c := int64(crc32.Checksum(ciphertext, crc32.MakeTable(crc32.Castagnoli)))

	testcases := []struct {
		name            string
		encryptResponse *kmspb.EncryptResponse
	}{
		{
			name: "verified_additional_authenticated_data_crc32c is false",
			encryptResponse: &kmspb.EncryptResponse{
				Ciphertext:              ciphertext,
				CiphertextCrc32C:        wrapperspb.Int64(ciphertextCrc32c),
				VerifiedPlaintextCrc32C: true,
				VerifiedAdditionalAuthenticatedDataCrc32C: false,
			},
		},
		{
			name: "verified_additional_authenticated_data_crc32c missing",
			encryptResponse: &kmspb.EncryptResponse{
				Ciphertext:              ciphertext,
				CiphertextCrc32C:        wrapperspb.Int64(ciphertextCrc32c),
				VerifiedPlaintextCrc32C: true,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			client := initializeGRPCClientWithResponse(t, tc.encryptResponse, nil)

			aead := newGRPCAEAD("key name", client)
			// Encryption should fail for all additional authenticated data (empty or non-empty).
			_, err := aead.EncryptWithContext(t.Context(), plaintext, []byte("additional data"))
			if err == nil {
				t.Errorf("a.Encrypt err = nil, want error")
			}
			_, err = aead.EncryptWithContext(t.Context(), plaintext, []byte(""))
			if err == nil {
				t.Errorf("a.Encrypt err = nil, want error")
			}
		})
	}
}

func TestGRPCEncrypt_FailsWithInvalidCiphertextCrc32c(t *testing.T) {
	testcases := []struct {
		name            string
		encryptResponse *kmspb.EncryptResponse
	}{
		{
			name: "ciphertext_crc32c does not match ciphertext",
			encryptResponse: &kmspb.EncryptResponse{
				Ciphertext:              []byte("ciphertext"),
				CiphertextCrc32C:        wrapperspb.Int64(1),
				VerifiedPlaintextCrc32C: true,
				VerifiedAdditionalAuthenticatedDataCrc32C: true,
			},
		},
		{
			name: "ciphertext_crc32c missing",
			encryptResponse: &kmspb.EncryptResponse{
				Ciphertext:              []byte("ciphertext"),
				VerifiedPlaintextCrc32C: true,
				VerifiedAdditionalAuthenticatedDataCrc32C: true,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			client := initializeGRPCClientWithResponse(t, tc.encryptResponse, nil)

			aead := newGRPCAEAD("key name", client)
			_, err := aead.EncryptWithContext(t.Context(), []byte("plaintext"), []byte("additional data"))
			if err == nil {
				t.Errorf("a.Encrypt err = nil, want error")
			}
		})
	}
}

func TestGRPCEncrypt_Success(t *testing.T) {
	ciphertext := []byte("ciphertext")
	ciphertextCrc32c := int64(crc32.Checksum(ciphertext, crc32.MakeTable(crc32.Castagnoli)))

	client := initializeGRPCClientWithResponse(t, &kmspb.EncryptResponse{
		Name:                    "key name",
		Ciphertext:              ciphertext,
		CiphertextCrc32C:        wrapperspb.Int64(ciphertextCrc32c),
		VerifiedPlaintextCrc32C: true,
		VerifiedAdditionalAuthenticatedDataCrc32C: true,
	}, nil)

	aead := newGRPCAEAD("key name", client)
	gotCiphertext, err := aead.EncryptWithContext(t.Context(), []byte("plaintext"), []byte("additional data"))
	if err != nil {
		t.Errorf("a.Encrypt err = %q, want nil", err)
	}
	if !bytes.Equal(gotCiphertext, ciphertext) {
		t.Errorf("Returned ciphertext: %q, want: %q", gotCiphertext, ciphertext)
	}
}

func TestGRPCDecrypt_FailsWithInvalidPlaintextCrc32c(t *testing.T) {
	testcases := []struct {
		name            string
		decryptResponse *kmspb.DecryptResponse
	}{
		{
			name: "plaintext_crc32c does not match plaintext",
			decryptResponse: &kmspb.DecryptResponse{
				Plaintext:       []byte("plaintext"),
				PlaintextCrc32C: wrapperspb.Int64(1),
			},
		},
		{
			name: "plaintext_crc32c missing",
			decryptResponse: &kmspb.DecryptResponse{
				Plaintext: []byte("plaintext"),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			client := initializeGRPCClientWithResponse(t, nil, tc.decryptResponse)

			aead := newGRPCAEAD("key name", client)
			_, err := aead.DecryptWithContext(t.Context(), []byte("ciphertext"), []byte("additional data"))
			if err == nil {
				t.Errorf("a.Decrypt err = nil, want error")
			}
		})
	}
}

func TestGRPCDecrypt_Success(t *testing.T) {
	plaintext := []byte("plaintext")
	plaintextCrc32c := int64(crc32.Checksum(plaintext, crc32.MakeTable(crc32.Castagnoli)))

	client := initializeGRPCClientWithResponse(t, nil, &kmspb.DecryptResponse{
		Plaintext:       plaintext,
		PlaintextCrc32C: wrapperspb.Int64(plaintextCrc32c),
	})

	aead := newGRPCAEAD("key name", client)
	gotPlaintext, err := aead.DecryptWithContext(t.Context(), []byte("ciphertext"), []byte("additional data"))
	if err != nil {
		t.Errorf("a.Decrypt err = %q, want nil", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Errorf("Returned plaintext: %q, want: %q", gotPlaintext, plaintext)
	}
}
