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
	"testing"
)

const (
	macKeyName               = "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/1"
	macKeyNameWrongFormat    = "projects/P1/locations/L1/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions"
	macKeyNameWithoutVersion = "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1"
)

func TestNewGRPCMAC_NilKmsClientFails(t *testing.T) {
	_, err := NewGRPCMAC(macKeyName, nil)
	if err == nil {
		t.Errorf("NewGRPCMAC succeeded, want error")
	}
}

func TestNewGRPCMAC_Fails(t *testing.T) {
	type testCase struct {
		name    string
		keyName string
	}
	testCases := []testCase{
		{
			name:    "empty key name",
			keyName: "",
		},
		{
			name:    "malformed key name",
			keyName: macKeyNameWrongFormat,
		},
		{
			name:    "key name without crypto key version",
			keyName: macKeyNameWithoutVersion,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gcpKMSClient := setupMockKMSClient(t.Context(), t, &mockKMS{})

			if _, err := NewGRPCMAC(tc.keyName, gcpKMSClient); err == nil {
				t.Errorf("NewGRPCMAC(%q) succeeded, want error", tc.keyName)
			}
		})
	}
}

// Placeholder - will be replaced by real tests in the next commit.
func TestGRPCMAC_ComputeMACNotYetImplemented(t *testing.T) {
	mac, err := NewGRPCMAC(macKeyName, setupMockKMSClient(t.Context(), t, &mockKMS{}))
	if err != nil {
		t.Fatalf("NewGRPCMAC failed: %v", err)
	}
	if _, err := mac.ComputeMAC([]byte{}); err == nil {
		t.Errorf("mac.ComputeMAC succeeded, want error")
	}
}

// Placeholder - will be replaced by real tests in the next commit.
func TestGRPCMAC_VerifyMACNotYetImplemented(t *testing.T) {
	mac, err := NewGRPCMAC(macKeyName, setupMockKMSClient(t.Context(), t, &mockKMS{}))
	if err != nil {
		t.Fatalf("NewGRPCMAC failed: %v", err)
	}
	if err := mac.VerifyMAC([]byte{}, []byte{}); err == nil {
		t.Errorf("mac.VerifyMAC succeeded, want error")
	}
}
