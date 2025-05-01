// Copyright 2019 Google LLC
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

package gcpkms_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	// Placeholder for internal flag import.
	// context is used to cancel outstanding requests
	"google.golang.org/api/option"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
)

const (
	keyURI = "gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key"
)

var (
	credFile = "testdata/gcp/credential.json"
)

// Placeholder for internal initialization.

func testFilePath(t *testing.T, filename string) string {
	t.Helper()
	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if ok {
		workspaceDir, ok := os.LookupEnv("TEST_WORKSPACE")
		if !ok {
			t.Fatal("TEST_WORKSPACE not found")
		}
		return filepath.Join(srcDir, workspaceDir, filename)
	}
	return filepath.Join("../..", filename)
}

func TestGetAeadWithEnvelopeAead(t *testing.T) {
	ctx := context.Background()
	gcpClient, err := gcpkms.NewClientWithOptions(ctx, keyURI, option.WithCredentialsFile(testFilePath(t, credFile)))
	if err != nil {
		t.Fatalf("gcpkms.NewClientWithOptions() err = %q, want nil", err)
	}
	kekAEAD, err := gcpClient.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("gcpClient.GetAEAD(keyURI) err = %q, want nil", err)
	}

	dekTemplate := aead.AES128CTRHMACSHA256KeyTemplate()
	a := aead.NewKMSEnvelopeAEAD2(dekTemplate, kekAEAD)
	if err != nil {
		t.Fatalf("a.Encrypt(plaintext, associatedData) err = %q, want nil", err)
	}
	plaintext := []byte("message")
	associatedData := []byte("example KMS envelope AEAD encryption")

	ciphertext, err := a.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("a.Encrypt(plaintext, associatedData) err = %q, want nil", err)
	}
	gotPlaintext, err := a.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("a.Decrypt(ciphertext, associatedData) err = %q, want nil", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Errorf("a.Decrypt() = %q, want %q", gotPlaintext, plaintext)
	}

	_, err = a.Decrypt(ciphertext, []byte("invalid associatedData"))
	if err == nil {
		t.Error("a.Decrypt(ciphertext, []byte(\"invalid associatedData\")) err = nil, want error")
	}
}

func TestAeadWithTransportGRPC(t *testing.T) {
	ctx := context.Background()

	opts := []gcpkms.Option{
		gcpkms.WithTransport(gcpkms.TransportGRPC),
		gcpkms.WithGoogleAPIClientOptions(option.WithCredentialsFile(testFilePath(t, credFile))),
	}
	gcpClient, err := gcpkms.NewClient(ctx, keyURI, opts...)
	if err != nil {
		t.Fatalf("gcpkms.NewClient() err = %q, want nil", err)
	}
	aead, err := gcpClient.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("gcpClient.GetAEAD(keyURI) err = %q, want nil", err)
	}

	testcases := []struct {
		name           string
		plaintext      []byte
		associatedData []byte
	}{
		{
			name:           "empty_plaintext",
			plaintext:      []byte(""),
			associatedData: []byte("authenticated data"),
		},
		{
			name:           "empty_associated_data",
			plaintext:      []byte("plaintext"),
			associatedData: []byte(""),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := aead.Encrypt(tc.plaintext, tc.associatedData)
			if err != nil {
				t.Fatalf("aead.EncryptWithContext(plaintext, associatedData) err = %q, want nil", err)
			}
			gotPlaintext, err := aead.Decrypt(ciphertext, tc.associatedData)
			if err != nil {
				t.Fatalf("aead.DecryptWithContext(ciphertext, associatedData) err = %q, want nil", err)
			}
			if !bytes.Equal(gotPlaintext, tc.plaintext) {
				t.Errorf("aead.DecryptWithContext() = %q, want %q", gotPlaintext, tc.plaintext)
			}
		})
	}
}

func TestAeadCrossClient(t *testing.T) {
	ctx := context.Background()

	httpOpts := []gcpkms.Option{
		gcpkms.WithTransport(gcpkms.TransportREST),
		gcpkms.WithGoogleAPIClientOptions(option.WithCredentialsFile(testFilePath(t, credFile))),
	}
	httpClient, err := gcpkms.NewClient(ctx, keyURI, httpOpts...)
	if err != nil {
		t.Fatalf("gcpkms.NewClient() err = %q, want nil", err)
	}
	httpAEAD, err := httpClient.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("httpClient.GetAEAD(keyURI) err = %q, want nil", err)
	}

	grpcOpts := []gcpkms.Option{
		gcpkms.WithTransport(gcpkms.TransportGRPC),
		gcpkms.WithGoogleAPIClientOptions(option.WithCredentialsFile(testFilePath(t, credFile))),
	}
	grpcClient, err := gcpkms.NewClient(ctx, keyURI, grpcOpts...)
	if err != nil {
		t.Fatalf("gcpkms.NewClient() err = %q, want nil", err)
	}
	grpcAEAD, err := grpcClient.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("grpcClient.GetAEAD(keyURI) err = %q, want nil", err)
	}

	testcases := []struct {
		name           string
		plaintext      []byte
		associatedData []byte
	}{
		{
			name:           "empty_plaintext",
			plaintext:      []byte(""),
			associatedData: []byte("authenticated data"),
		},
		{
			name:           "empty_associated_data",
			plaintext:      []byte("plaintext"),
			associatedData: []byte(""),
		},
	}

	for _, tc := range testcases {
		t.Run("encrypt_with_grpc_"+tc.name, func(t *testing.T) {
			ciphertext, err := grpcAEAD.Encrypt(tc.plaintext, tc.associatedData)
			if err != nil {
				t.Fatalf("grpcAEAD.Encrypt(plaintext, associatedData) err = %q, want nil", err)
			}
			gotPlaintext, err := httpAEAD.Decrypt(ciphertext, tc.associatedData)
			if err != nil {
				t.Fatalf("httpAEAD.Decrypt(ciphertext, associatedData) err = %q, want nil", err)
			}
			if !bytes.Equal(gotPlaintext, tc.plaintext) {
				t.Errorf("httpAEAD.Decrypt() = %q, want %q", gotPlaintext, tc.plaintext)
			}
		})
		t.Run("encrypt_with_http_"+tc.name, func(t *testing.T) {
			ciphertext, err := httpAEAD.Encrypt(tc.plaintext, tc.associatedData)
			if err != nil {
				t.Fatalf("httpAEAD.Encrypt(plaintext, associatedData) err = %q, want nil", err)
			}
			gotPlaintext, err := grpcAEAD.Decrypt(ciphertext, tc.associatedData)
			if err != nil {
				t.Fatalf("grpcAEAD.Decrypt(ciphertext, associatedData) err = %q, want nil", err)
			}
			if !bytes.Equal(gotPlaintext, tc.plaintext) {
				t.Errorf("grpcAEAD.Decrypt() = %q, want %q", gotPlaintext, tc.plaintext)
			}
		})
	}
}

func TestAead(t *testing.T) {
	ctx := context.Background()
	gcpClient, err := gcpkms.NewClientWithOptions(ctx, keyURI, option.WithCredentialsFile(testFilePath(t, credFile)))
	if err != nil {
		t.Fatalf("gcpkms.NewClientWithOptions() err = %q, want nil", err)
	}
	aead, err := gcpClient.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("gcpClient.GetAEAD(keyURI) err = %q, want nil", err)
	}

	testcases := []struct {
		name           string
		plaintext      []byte
		associatedData []byte
	}{
		{
			name:           "empty_plaintext",
			plaintext:      []byte(""),
			associatedData: []byte("authenticated data"),
		},
		{
			name:           "empty_associated_data",
			plaintext:      []byte("plaintext"),
			associatedData: []byte(""),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := aead.Encrypt(tc.plaintext, tc.associatedData)
			if err != nil {
				t.Fatalf("aead.Encrypt(plaintext, associatedData) err = %q, want nil", err)
			}
			gotPlaintext, err := aead.Decrypt(ciphertext, tc.associatedData)
			if err != nil {
				t.Fatalf("aead.Decrypt(ciphertext, associatedData) err = %q, want nil", err)
			}
			if !bytes.Equal(gotPlaintext, tc.plaintext) {
				t.Errorf("aead.Decrypt() = %q, want %q", gotPlaintext, tc.plaintext)
			}
		})
	}
}

func TestAeadWithContext(t *testing.T) {
	ctx := context.Background()
	aeadWithContext, err := gcpkms.GetAEADWithContext(ctx, keyURI, gcpkms.WithGoogleAPIClientOptions(option.WithCredentialsFile(testFilePath(t, credFile))))
	if err != nil {
		t.Fatalf("gcpkms.GetAEADWithContext() err = %q, want nil", err)
	}

	plaintext := []byte("message")
	associatedData := []byte("example context-aware encryption")

	ciphertext, err := aeadWithContext.EncryptWithContext(ctx, plaintext, associatedData)
	if err != nil {
		t.Fatalf("aeadWithContext.EncryptWithContext(ctx, plaintext, associatedData) err = %q, want nil", err)
	}

	gotPlaintext, err := aeadWithContext.DecryptWithContext(ctx, ciphertext, associatedData)

	if err != nil {
		t.Fatalf("aeadWithContext.DecryptWithContext(ctx, ciphertext, associatedData) err = %q, want nil", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Errorf("aeadWithContext.DecryptWithContext() = %q, want %q", gotPlaintext, plaintext)
	}
}
