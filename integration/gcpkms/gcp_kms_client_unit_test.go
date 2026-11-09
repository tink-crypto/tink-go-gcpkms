// Copyright 2026 Google LLC
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
	"testing"

	"google.golang.org/api/option"
)

func newTestRESTClient(t *testing.T, uriPrefix string) *Client {
	t.Helper()
	c, err := NewClient(
		t.Context(),
		uriPrefix,
		WithTransport(TransportREST),
		WithGoogleAPIClientOptions(option.WithoutAuthentication()),
	)
	if err != nil {
		t.Fatalf("NewClient(%q) err = %v, want nil", uriPrefix, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestClientSupported_BoundToCryptoKey(t *testing.T) {
	const boundURI = "gcp-kms://projects/p/locations/us/keyRings/r/cryptoKeys/prod"
	c := newTestRESTClient(t, boundURI)

	tests := []struct {
		name   string
		keyURI string
		want   bool
	}{
		{
			name:   "exact_match",
			keyURI: boundURI,
			want:   true,
		},
		{
			name:   "case_insensitive_scheme",
			keyURI: "GCP-KMS://projects/p/locations/us/keyRings/r/cryptoKeys/prod",
			want:   true,
		},
		{
			name:   "case_sensitive_resource_name",
			keyURI: "gcp-kms://projects/p/locations/us/keyRings/r/cryptoKeys/PROD",
			want:   false,
		},
		{
			name:   "different_keyring",
			keyURI: "gcp-kms://projects/p/locations/us/keyRings/other/cryptoKeys/prod",
			want:   false,
		},
		{
			name:   "sibling_key_sharing_prefix_with_hyphen",
			keyURI: boundURI + "-attacker",
			want:   false,
		},
		{
			name:   "sibling_key_sharing_prefix_word",
			keyURI: boundURI + "uction",
			want:   false,
		},
		{
			name:   "appended_crypto_key_version",
			keyURI: boundURI + "/cryptoKeyVersions/7",
			want:   false,
		},
		{
			name:   "trailing_slash",
			keyURI: boundURI + "/",
			want:   false,
		},
		{
			name:   "parent_keyring_prefix",
			keyURI: "gcp-kms://projects/p/locations/us/keyRings/r",
			want:   false,
		},
		{
			name:   "non_gcp_scheme",
			keyURI: "aws-kms://projects/p/locations/us/keyRings/r/cryptoKeys/prod",
			want:   false,
		},
		{
			name:   "empty_uri",
			keyURI: "",
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.Supported(tc.keyURI); got != tc.want {
				t.Errorf("c.Supported(%q) = %v, want %v (bound to %q)", tc.keyURI, got, tc.want, boundURI)
			}
		})
	}
}

func TestClientSupported_BoundToCryptoKeyVersion(t *testing.T) {
	const boundURI = "gcp-kms://projects/p/locations/us/keyRings/r/cryptoKeys/prod/cryptoKeyVersions/1"
	c := newTestRESTClient(t, boundURI)

	tests := []struct {
		name   string
		keyURI string
		want   bool
	}{
		{
			name:   "exact_match",
			keyURI: boundURI,
			want:   true,
		},
		{
			name:   "sibling_version_sharing_prefix",
			keyURI: boundURI + "0",
			want:   false,
		},
		{
			name:   "different_version",
			keyURI: "gcp-kms://projects/p/locations/us/keyRings/r/cryptoKeys/prod/cryptoKeyVersions/2",
			want:   false,
		},
		{
			name:   "parent_crypto_key",
			keyURI: "gcp-kms://projects/p/locations/us/keyRings/r/cryptoKeys/prod",
			want:   false,
		},
		{
			name:   "appended_subpath",
			keyURI: boundURI + "/publicKey",
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.Supported(tc.keyURI); got != tc.want {
				t.Errorf("c.Supported(%q) = %v, want %v (bound to %q)", tc.keyURI, got, tc.want, boundURI)
			}
		})
	}
}

func TestClientSupported_GenericPrefix(t *testing.T) {
	c := newTestRESTClient(t, "gcp-kms://")

	tests := []struct {
		name   string
		keyURI string
		want   bool
	}{
		{
			name:   "crypto_key_1",
			keyURI: "gcp-kms://projects/p1/locations/us/keyRings/r1/cryptoKeys/k1",
			want:   true,
		},
		{
			name:   "crypto_key_2",
			keyURI: "gcp-kms://projects/p2/locations/global/keyRings/r2/cryptoKeys/k2",
			want:   true,
		},
		{
			name:   "uppercase_scheme",
			keyURI: "GCP-KMS://projects/p1/locations/us/keyRings/r1/cryptoKeys/k1",
			want:   true,
		},
		{
			name:   "non_gcp_scheme",
			keyURI: "aws-kms://arn:aws:kms:us-west-2:acc:other/key3",
			want:   false,
		},
		{
			name:   "incomplete_scheme",
			keyURI: "gcp-kms:",
			want:   false,
		},
		{
			name:   "empty_uri",
			keyURI: "",
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.Supported(tc.keyURI); got != tc.want {
				t.Errorf("c.Supported(%q) = %v, want %v", tc.keyURI, got, tc.want)
			}
		})
	}
}

func TestClientSupported_PartialResourcePrefix(t *testing.T) {
	for _, prefix := range []string{
		"gcp-kms://projects/my-proj",
		"gcp-kms://projects/my-proj/",
	} {
		t.Run(prefix, func(t *testing.T) {
			c := newTestRESTClient(t, prefix)

			const inProject = "gcp-kms://projects/my-proj/locations/us/keyRings/r/cryptoKeys/prod"
			if !c.Supported(inProject) {
				t.Errorf("c.Supported(%q) = false, want true (prefix %q)", inProject, prefix)
			}

			const siblingProject = "gcp-kms://projects/my-proj-other/locations/us/keyRings/r/cryptoKeys/prod"
			if c.Supported(siblingProject) {
				t.Errorf("c.Supported(%q) = true, want false (prefix %q)", siblingProject, prefix)
			}
		})
	}
}

func TestClientSupported_ZeroValueClient(t *testing.T) {
	var c Client
	if c.Supported("gcp-kms://projects/p/locations/us/keyRings/r/cryptoKeys/prod") {
		t.Errorf("zero-value Client.Supported(validURI) = true, want false")
	}
	if c.Supported("") {
		t.Errorf("zero-value Client.Supported(\"\") = true, want false")
	}
}

func TestClientGetAEAD_RejectsUnsupportedPrefixBypass(t *testing.T) {
	const boundURI = "gcp-kms://projects/p/locations/us/keyRings/r/cryptoKeys/prod"
	c := newTestRESTClient(t, boundURI)

	if _, err := c.GetAEAD(boundURI); err != nil {
		t.Errorf("c.GetAEAD(%q) err = %v, want nil", boundURI, err)
	}
	for _, unsupported := range []string{
		boundURI + "-attacker",
		boundURI + "/cryptoKeyVersions/7",
		"gcp-kms://projects/p/locations/us/keyRings/other/cryptoKeys/prod",
	} {
		if _, err := c.GetAEAD(unsupported); err == nil {
			t.Errorf("c.GetAEAD(%q) err = nil, want error", unsupported)
		}
	}
}
