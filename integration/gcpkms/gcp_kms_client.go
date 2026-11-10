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

// Package gcpkms provides integration with the [GCP Cloud KMS].
//
// [GCP Cloud KMS]: https://cloud.google.com/kms/docs/quickstart.
package gcpkms

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"cloud.google.com/go/kms/apiv1"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/tink"
)

const (
	gcpPrefix = "gcp-kms://"
)

var (
	errCred       = errors.New("invalid credential path")
	tinkUserAgent = "Tink/" + tink.Version + " Golang/" + runtime.Version()
)

// Transport indicates how the client should communicate with the KMS backend.
type Transport int

const (
	// TransportGRPC communicates with Cloud KMS using gRPC.
	TransportGRPC Transport = 1 + iota
	// TransportREST communicates with Cloud KMS using the REST API via HTTP.
	TransportREST
)

// Client represents a GCP KMS client.
type Client struct {
	keyURIPrefix string
	restKMS      *cloudkms.Service
	grpcKMS      *kms.KeyManagementClient
}

var _ registry.KMSClient = (*Client)(nil)

// NewClient returns a [Client] for the given key URI prefix.
//
// uriPrefix must have the following format:
//
//	gcp-kms://[path]
func NewClient(ctx context.Context, uriPrefix string, opts ...Option) (*Client, error) {
	if !strings.HasPrefix(strings.ToLower(uriPrefix), gcpPrefix) {
		return nil, fmt.Errorf("uriPrefix must start with %s", gcpPrefix)
	}
	var o options

	for _, opt := range DefaultOptions {
		opt(&o)
	}
	for _, opt := range opts {
		opt(&o)
	}

	o.apiOptions = append(o.apiOptions, option.WithUserAgent(tinkUserAgent))

	c := &Client{keyURIPrefix: uriPrefix}

	switch o.transport {
	case TransportGRPC:
		kmsClient, err := kms.NewKeyManagementClient(ctx, o.apiOptions...)
		if err != nil {
			return nil, err
		}
		c.grpcKMS = kmsClient
	case TransportREST:
		kmsService, err := cloudkms.NewService(ctx, o.apiOptions...)
		if err != nil {
			return nil, err
		}
		c.restKMS = kmsService
	default:
		return nil, fmt.Errorf("invalid transport specified: %v", o.transport)
	}

	return c, nil
}

// GetAEADWithContext returns a [tink.AEADWithContext] backed by keyURI.
func GetAEADWithContext(ctx context.Context, keyURI string, opts ...Option) (tink.AEADWithContext, error) {
	c, err := NewClient(ctx, keyURI, opts...)
	if err != nil {
		return nil, err
	}
	if c.grpcKMS == nil {
		return nil, errors.New("AEADWithContext is only supported when using GRPC")
	}
	keyName := strings.TrimPrefix(keyURI, gcpPrefix)
	return newGRPCAEAD(keyName, c.grpcKMS), nil
}

// options holds the configuration options for a gcpkms.Client, including the transport protocol
// and API client options.
type options struct {
	transport  Transport
	apiOptions []option.ClientOption
}

// Option is a functional option for configuring a gcpkms.Client.
type Option func(*options)

// WithTransport configures the transport protocol used by the gcpkms.Client.
//
// By default, [TransportGRPC] is used.
func WithTransport(transport Transport) Option {
	return func(opts *options) {
		opts.transport = transport
	}
}

// WithGoogleAPIClientOptions configures the gcpkms.Client with Google API client options.
func WithGoogleAPIClientOptions(apiOptions ...option.ClientOption) Option {
	return func(opts *options) {
		opts.apiOptions = apiOptions
	}
}

// DefaultOptions are the default configuration options for a [Client].
var DefaultOptions = []Option{
	WithTransport(TransportGRPC),
}

// NewClientWithOptions returns a new [registry.KMSClient] with provided Google API
// options to handle keys whose URI start with uriPrefix.
//
// uriPrefix must have the following format:
//
//	gcp-kms://[path]
//
// This client uses [TransportREST] for communication with the GCP KMS backend.
//
// Deprecated: Use [NewClient] and [WithTransport] instead.
func NewClientWithOptions(ctx context.Context, uriPrefix string, opts ...option.ClientOption) (registry.KMSClient, error) {
	return NewClient(ctx, uriPrefix, WithTransport(TransportREST), WithGoogleAPIClientOptions(opts...))
}

// Supported returns true if this client does support keyURI.
func (c *Client) Supported(keyURI string) bool {
	return strings.HasPrefix(keyURI, c.keyURIPrefix)
}

// GetAEAD gets an AEAD backend by keyURI.
func (c *Client) GetAEAD(keyURI string) (tink.AEAD, error) {
	if !c.Supported(keyURI) {
		return nil, errors.New("unsupported keyURI")
	}

	keyName := strings.TrimPrefix(keyURI, gcpPrefix)

	switch {
	case c.grpcKMS != nil:
		return &aeadWithContextWrapper{AEADWithContext: newGRPCAEAD(keyName, c.grpcKMS)}, nil
	case c.restKMS != nil:
		return newGCPAEAD(keyName, c.restKMS), nil
	default:
		return nil, fmt.Errorf("no client present")
	}
}

// Close closes the client.
func (c *Client) Close() error {
	if c.grpcKMS != nil {
		return c.grpcKMS.Close()
	}
	return nil
}
