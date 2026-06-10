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
	"context"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	macData                                    = "data for mac"
	macWrongData                               = "wrong data for mac"
	macKeyName                                 = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/1"
	macKeyNameWrongFormat                      = "projects/P1/locations/L1/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions"
	macKeyNameWithoutVersion                   = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1"
	macKeyNameErrorMacSign                     = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/2"
	macKeyNameErrorDataCrc32cNotVerified       = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/3"
	macKeyNameErrorMacCrc32c                   = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/4"
	macKeyNameErrorWrongKeyNameSign            = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/5"
	macKeyNameErrorMacVerify                   = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/6"
	macKeyNameVerifyErrorDataCrc32cNotVerified = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/7"
	macKeyNameVerifyErrorMacCrc32cNotVerified  = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/8"
	macKeyNameVerifyErrorSuccessIntegrity      = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/9"
	macKeyNameVerifyErrorWrongKeyName          = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/10"
	macKeyNameVerifyErrorSuccessIntegrityFalse = "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/11"
)

func expectedMAC(data []byte) []byte {
	return slices.Concat([]byte("mac for "), data)
}

func (s *mockKMS) MacSign(ctx context.Context, req *kmspb.MacSignRequest) (*kmspb.MacSignResponse, error) {
	if req.GetName() == macKeyNameErrorMacSign {
		return nil, status.Error(codes.PermissionDenied, "Permission denied")
	}
	if req.GetDataCrc32C().GetValue() != computeChecksum(req.GetData()) {
		return nil, status.Error(codes.InvalidArgument, "invalid data checksum")
	}

	response := &kmspb.MacSignResponse{
		Name:               req.GetName(),
		Mac:                expectedMAC(req.GetData()),
		VerifiedDataCrc32C: true,
	}
	response.MacCrc32C = wrapperspb.Int64(computeChecksum(response.GetMac()))

	switch req.GetName() {
	case macKeyNameErrorWrongKeyNameSign:
		response.Name = macKeyName
	case macKeyNameErrorMacCrc32c:
		response.MacCrc32C = wrapperspb.Int64(1)
	case macKeyNameErrorDataCrc32cNotVerified:
		response.VerifiedDataCrc32C = false
	}

	return response, nil
}

func (s *mockKMS) MacVerify(ctx context.Context, req *kmspb.MacVerifyRequest) (*kmspb.MacVerifyResponse, error) {
	if req.GetName() == macKeyNameErrorMacVerify {
		return nil, status.Error(codes.PermissionDenied, "Permission denied")
	}
	if req.GetDataCrc32C().GetValue() != computeChecksum(req.GetData()) {
		return nil, status.Error(codes.InvalidArgument, "invalid data checksum")
	}
	if req.GetMacCrc32C().GetValue() != computeChecksum(req.GetMac()) {
		return nil, status.Error(codes.InvalidArgument, "invalid MAC checksum")
	}

	success := bytes.Equal(req.GetMac(), expectedMAC(req.GetData()))
	response := &kmspb.MacVerifyResponse{
		Name:                     req.GetName(),
		Success:                  success,
		VerifiedDataCrc32C:       true,
		VerifiedMacCrc32C:        true,
		VerifiedSuccessIntegrity: success,
	}

	switch req.GetName() {
	case macKeyNameVerifyErrorWrongKeyName:
		response.Name = macKeyName
	case macKeyNameVerifyErrorDataCrc32cNotVerified:
		response.VerifiedDataCrc32C = false
	case macKeyNameVerifyErrorMacCrc32cNotVerified:
		response.VerifiedMacCrc32C = false
	case macKeyNameVerifyErrorSuccessIntegrity:
		response.VerifiedSuccessIntegrity = false
	case macKeyNameVerifyErrorSuccessIntegrityFalse:
		response.Success = false
		response.VerifiedSuccessIntegrity = true
	}

	return response, nil
}

func initializeMAC(ctx context.Context, t *testing.T, keyName string) *GRPCMAC {
	t.Helper()
	gcpKMSClient := setupMockKMSClient(ctx, t, &mockKMS{})
	mac, err := NewGRPCMAC(keyName, gcpKMSClient)
	if err != nil {
		t.Fatalf("NewGRPCMAC failed: %v", err)
	}
	return mac
}

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

func TestGRPCMAC_ComputeMACFails(t *testing.T) {
	type testCase struct {
		name    string
		keyName string
		data    []byte
	}
	testCases := []testCase{
		{
			name:    "mac sign fails",
			keyName: macKeyNameErrorMacSign,
			data:    []byte(macData),
		},
		{
			name:    "input checksum fails",
			keyName: macKeyNameErrorDataCrc32cNotVerified,
			data:    []byte(macData),
		},
		{
			name:    "mac checksum mismatch",
			keyName: macKeyNameErrorMacCrc32c,
			data:    []byte(macData),
		},
		{
			name:    "mismatched key name in response",
			keyName: macKeyNameErrorWrongKeyNameSign,
			data:    []byte(macData),
		},
		{
			name:    "oversized input data",
			keyName: macKeyName,
			data:    bytes.Repeat([]byte("A"), kmsMaxMACDataSize+1),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mac := initializeMAC(t.Context(), t, tc.keyName)
			if _, err := mac.ComputeMAC(tc.data); err == nil {
				t.Errorf("mac.ComputeMAC(%q) succeeded, want error", tc.data)
			}
		})
	}
}

func TestGRPCMAC_ComputeMACSuccess(t *testing.T) {
	mac := initializeMAC(t.Context(), t, macKeyName)
	gotMAC, err := mac.ComputeMAC([]byte(macData))
	if err != nil {
		t.Fatalf("mac.ComputeMAC(%q) error = %v, want nil", macData, err)
	}
	if !bytes.Equal(gotMAC, expectedMAC([]byte(macData))) {
		t.Errorf("mac.ComputeMAC(%q) = %q, want %q", macData, gotMAC, expectedMAC([]byte(macData)))
	}
}

func TestGRPCMAC_VerifyMACFails(t *testing.T) {
	validMAC := expectedMAC([]byte(macData))

	type testCase struct {
		name    string
		keyName string
		mac     []byte
		data    []byte
	}
	testCases := []testCase{
		{
			name:    "mac verify fails",
			keyName: macKeyNameErrorMacVerify,
			mac:     validMAC,
			data:    []byte(macData),
		},
		{
			name:    "data checksum fails",
			keyName: macKeyNameVerifyErrorDataCrc32cNotVerified,
			mac:     validMAC,
			data:    []byte(macData),
		},
		{
			name:    "mac checksum fails",
			keyName: macKeyNameVerifyErrorMacCrc32cNotVerified,
			mac:     validMAC,
			data:    []byte(macData),
		},
		{
			name:    "success integrity false but success true fails",
			keyName: macKeyNameVerifyErrorSuccessIntegrity,
			mac:     validMAC,
			data:    []byte(macData),
		},
		{
			name:    "success integrity true but success false fails",
			keyName: macKeyNameVerifyErrorSuccessIntegrityFalse,
			mac:     validMAC,
			data:    []byte(macData),
		},
		{
			name:    "mismatched key name in response",
			keyName: macKeyNameVerifyErrorWrongKeyName,
			mac:     validMAC,
			data:    []byte(macData),
		},
		{
			name:    "wrong data",
			keyName: macKeyName,
			mac:     validMAC,
			data:    []byte(macWrongData),
		},
		{
			name:    "wrong mac",
			keyName: macKeyName,
			mac:     []byte("wrong mac"),
			data:    []byte(macData),
		},
		{
			name:    "oversized input data",
			keyName: macKeyName,
			mac:     validMAC,
			data:    bytes.Repeat([]byte("A"), kmsMaxMACDataSize+1),
		},
		{
			name:    "oversized input mac",
			keyName: macKeyName,
			mac:     bytes.Repeat([]byte("A"), kmsMaxMACSize+1),
			data:    []byte(macData),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mac := initializeMAC(t.Context(), t, tc.keyName)
			if err := mac.VerifyMAC(tc.mac, tc.data); err == nil {
				t.Errorf("mac.VerifyMAC(%q, %q) succeeded, want error", tc.mac, tc.data)
			}
		})
	}
}

func TestGRPCMAC_VerifyMACSuccess(t *testing.T) {
	mac := initializeMAC(t.Context(), t, macKeyName)
	tag, err := mac.ComputeMAC([]byte(macData))
	if err != nil {
		t.Fatalf("mac.ComputeMAC(%q) error = %v, want nil", macData, err)
	}
	if err := mac.VerifyMAC(tag, []byte(macData)); err != nil {
		t.Errorf("mac.VerifyMAC(%q, %q) error = %v, want nil", tag, macData, err)
	}
}
