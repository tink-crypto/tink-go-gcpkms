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
	"fmt"

	"cloud.google.com/go/kms/apiv1"
	"github.com/tink-crypto/tink-go/v2/tink"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

// kmsMaxMACDataSize represents the maximum size of the data that can be MAC-ed.
const kmsMaxMACDataSize = 64 * 1024

// kmsMaxMACSize represents the maximum size of the MAC that can be verified.
const kmsMaxMACSize = 64

// GRPCMAC represents a GCP GRPC-based KMS client to a particular MAC key URI.
type GRPCMAC struct {
	keyName string
	client  *kms.KeyManagementClient
}

var _ tink.MAC = (*GRPCMAC)(nil)

// NewGRPCMAC returns a new GCP KMS client that can be used for MAC operations.
func NewGRPCMAC(keyName string, client *kms.KeyManagementClient) (*GRPCMAC, error) {
	if err := validateKMSKeyName(keyName); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("kms client cannot be nil")
	}
	return &GRPCMAC{
		keyName: keyName,
		client:  client,
	}, nil
}

// ComputeMAC computes a MAC over the input data.
func (m *GRPCMAC) ComputeMAC(data []byte) ([]byte, error) {
	return m.ComputeMACWithContext(context.TODO(), data)
}

// ComputeMACWithContext computes a MAC over the input data using KMS.
func (m *GRPCMAC) ComputeMACWithContext(ctx context.Context, data []byte) ([]byte, error) {
	if len(data) > kmsMaxMACDataSize {
		return nil, fmt.Errorf("the input data (%d bytes) is larger than the allowed limit (%d bytes)", len(data), kmsMaxMACDataSize)
	}

	request := &kmspb.MacSignRequest{
		Name:       m.keyName,
		Data:       data,
		DataCrc32C: wrapperspb.Int64(computeChecksum(data)),
	}

	response, err := m.client.MacSign(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS MacSign failed: %w", err)
	}

	if response.GetName() != m.keyName {
		return nil, fmt.Errorf("the response key name %q does not match the requested key name %q", response.GetName(), m.keyName)
	}
	if !response.GetVerifiedDataCrc32C() {
		return nil, fmt.Errorf("checking the input checksum failed")
	}
	if response.GetMacCrc32C().GetValue() != computeChecksum(response.GetMac()) {
		return nil, fmt.Errorf("MAC checksum mismatch")
	}
	return response.GetMac(), nil
}

// VerifyMAC verifies whether mac is a correct MAC for data.
func (m *GRPCMAC) VerifyMAC(mac, data []byte) error {
	return m.VerifyMACWithContext(context.TODO(), mac, data)
}

// VerifyMACWithContext verifies whether mac is a correct MAC for data using KMS.
func (m *GRPCMAC) VerifyMACWithContext(ctx context.Context, mac, data []byte) error {
	if len(data) > kmsMaxMACDataSize {
		return fmt.Errorf("the input data (%d bytes) is larger than the allowed limit (%d bytes)", len(data), kmsMaxMACDataSize)
	}
	if len(mac) > kmsMaxMACSize {
		return fmt.Errorf("the input MAC (%d bytes) is larger than the allowed limit (%d bytes)", len(mac), kmsMaxMACSize)
	}

	request := &kmspb.MacVerifyRequest{
		Name:       m.keyName,
		Data:       data,
		DataCrc32C: wrapperspb.Int64(computeChecksum(data)),
		Mac:        mac,
		MacCrc32C:  wrapperspb.Int64(computeChecksum(mac)),
	}

	response, err := m.client.MacVerify(ctx, request)
	if err != nil {
		return fmt.Errorf("GCP KMS MacVerify failed: %w", err)
	}

	if response.GetName() != m.keyName {
		return fmt.Errorf("the response key name %q does not match the requested key name %q", response.GetName(), m.keyName)
	}
	if !response.GetVerifiedDataCrc32C() {
		return fmt.Errorf("checking the input data checksum failed")
	}
	if !response.GetVerifiedMacCrc32C() {
		return fmt.Errorf("checking the MAC checksum failed")
	}
	if response.GetVerifiedSuccessIntegrity() != response.GetSuccess() {
		return fmt.Errorf("checking the verification result integrity failed")
	}
	if !response.GetSuccess() {
		return fmt.Errorf("MAC verification failed")
	}
	return nil
}
