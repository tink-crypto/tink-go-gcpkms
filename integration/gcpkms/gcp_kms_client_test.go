// Copyright 2017 Google LLC
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
	"log"

	"google.golang.org/api/option"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
)

func Example() {
	const keyURI = "gcp-kms://......"
	ctx := context.Background()
	// Replace "/mysecurestorage/credentials.json" with actual path or other auth method if needed for a real run.
	credentialsOpt := option.WithCredentialsFile("/mysecurestorage/credentials.json")

	// Get the KEK AEAD as AEADWithContext directly.
	kekAEAD, err := gcpkms.GetAEADWithContext(ctx, keyURI, gcpkms.WithGoogleAPIClientOptions(credentialsOpt))
	if err != nil {
		log.Fatalf("gcpkms.GetAEADWithContext failed: %v", err)
	}

	// Create the KMS envelope AEAD primitive using AEADWithContext.
	dekTemplate := aead.AES128CTRHMACSHA256KeyTemplate()
	envelopeAEAD, err := aead.NewKMSEnvelopeAEADWithContext(dekTemplate, kekAEAD)
	if err != nil {
		log.Fatalf("aead.NewKMSEnvelopeAEADWithContext failed: %v", err)
	}

	// Use the primitive with context.
	plaintext := []byte("message for envelope with context")
	associatedData := []byte("example KMS envelope AEADWithContext encryption")

	ciphertext, err := envelopeAEAD.EncryptWithContext(ctx, plaintext, associatedData)
	if err != nil {
		log.Fatalf("envelopeAEAD.EncryptWithContext failed: %v", err)
	}

	decryptedPlaintext, err := envelopeAEAD.DecryptWithContext(ctx, ciphertext, associatedData)
	if err != nil {
		log.Fatalf("envelopeAEAD.DecryptWithContext failed: %v", err)
	}

	if !bytes.Equal(plaintext, decryptedPlaintext) {
		log.Fatalf("envelope decrypted text (%s) does not match original plaintext (%s)", decryptedPlaintext, plaintext)
	}
}

// Example_withoutContext demonstrates how to obtain a tink.AEAD from the GCP KMS client.
// This approach is useful when working with APIs or parts of Tink that expect a tink.AEAD instance
// rather than a tink.AEADWithContext.
func Example_aeadWithoutContext() {
	const keyURI = "gcp-kms://......"
	ctx := context.Background()
	// Replace "/mysecurestorage/credentials.json" with actual path or other auth method if needed for a real run.
	credentialsOpt := option.WithCredentialsFile("/mysecurestorage/credentials.json")

	// Create a new GCP KMS client.
	// By default, NewClient uses gRPC.
	kmsClient, err := gcpkms.NewClient(ctx, keyURI, gcpkms.WithGoogleAPIClientOptions(credentialsOpt))
	if err != nil {
		log.Fatalf("gcpkms.NewClient failed: %v", err)
	}

	// Get a regular tink.AEAD primitive from the client.
	// If the client is gRPC-based (default), this wraps the underlying AEADWithContext.
	regularAEAD, err := kmsClient.GetAEAD(keyURI)
	if err != nil {
		log.Fatalf("kmsClient.GetAEAD failed: %v", err)
	}

	// Use the tink.AEAD primitive.
	plaintext := []byte("message for regular AEAD")
	associatedData := []byte("example regular AEAD encryption")

	ciphertext, err := regularAEAD.Encrypt(plaintext, associatedData)
	if err != nil {
		log.Fatalf("regularAEAD.Encrypt failed: %v", err)
	}

	decryptedPlaintext, err := regularAEAD.Decrypt(ciphertext, associatedData)
	if err != nil {
		log.Fatalf("regularAEAD.Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decryptedPlaintext) {
		log.Fatalf("regular AEAD decrypted text (%s) does not match original plaintext (%s)", decryptedPlaintext, plaintext)
	}
}
