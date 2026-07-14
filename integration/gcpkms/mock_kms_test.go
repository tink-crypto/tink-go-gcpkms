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
	"net"
	"testing"

	"cloud.google.com/go/kms/apiv1"
	"google.golang.org/api/option"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	// Placeholder for internal proto import.
	kmspbgrpc "google.golang.org/genproto/googleapis/cloud/kms/v1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// mockKMS provides a fake KMS implementation for testing.
//
// Test methods can be added in primitive specific test files.
type mockKMS struct {
	kmspbgrpc.UnimplementedKeyManagementServiceServer
	getPublicKeyFormatRequests []kmspb.PublicKey_PublicKeyFormat
	lastAsymmetricSignRequest  *kmspb.AsymmetricSignRequest
}

func setupMockKMSClient(ctx context.Context, t *testing.T, mockServer *mockKMS) *kms.KeyManagementClient {
	t.Helper()

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()

	kmspbgrpc.RegisterKeyManagementServiceServer(s, mockServer)

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
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	gcpKMSClient, err := kms.NewKeyManagementClient(ctx, option.WithGRPCConn(conn))
	if err != nil {
		t.Fatalf("kms.NewKeyManagementClient with GRPCConn failed: %v", err)
	}
	return gcpKMSClient
}
