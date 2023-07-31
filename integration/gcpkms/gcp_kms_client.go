// Copyright 2017 Google Inc.
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
//
////////////////////////////////////////////////////////////////////////////////

// Package gcpkms provides integration with the GCP Cloud KMS.
// Tink APIs work with GCP and AWS KMS.
package gcpkms

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/api/option"

	kms "cloud.google.com/go/kms/apiv1"
)

const (
	gcpPrefix = "gcp-kms://"
)

var (
	tinkUserAgent = "Tink/" + tink.Version + " Golang/" + runtime.Version()
)

// gcpClient represents a client that connects to the GCP KMS backend.
type gcpClient struct {
	keyURIPrefix string
	kms          *kms.KeyManagementClient
}

var _ registry.KMSClient = (*gcpClient)(nil)

// NewClientWithOptions returns a new GCP KMS client with provided Google API
// options to handle keys with uriPrefix prefix.
// uriPrefix must have the following format: 'gcp-kms://[:path]'.
func NewClientWithOptions(ctx context.Context, uriPrefix string, opts ...option.ClientOption) (registry.KMSClient, error) {
	if !strings.HasPrefix(strings.ToLower(uriPrefix), gcpPrefix) {
		return nil, fmt.Errorf("uriPrefix must start with %s", gcpPrefix)
	}

	opts = append(opts, option.WithUserAgent(tinkUserAgent))
	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return &gcpClient{
		keyURIPrefix: uriPrefix,
		kms:          client,
	}, nil
}

// Supported true if this client does support keyURI
func (c *gcpClient) Supported(keyURI string) bool {
	return strings.HasPrefix(keyURI, c.keyURIPrefix)
}

// GetAEAD gets an AEAD backend by keyURI.
func (c *gcpClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	if !c.Supported(keyURI) {
		return nil, errors.New("unsupported keyURI")
	}

	uri := strings.TrimPrefix(keyURI, gcpPrefix)
	return newGCPAEAD(uri, c.kms), nil
}
