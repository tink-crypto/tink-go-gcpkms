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
	"fmt"

	"cloud.google.com/go/kms/apiv1"
	"github.com/tink-crypto/tink-go/v2/tink"
)

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
	return nil, fmt.Errorf("not yet implemented")
}

// VerifyMAC verifies whether mac is a correct MAC for data.
func (m *GRPCMAC) VerifyMAC(mac, data []byte) error {
	return fmt.Errorf("not yet implemented")
}
