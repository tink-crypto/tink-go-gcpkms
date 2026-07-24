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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	// Placeholder for internal proto import.
	kmspbgrpc "google.golang.org/genproto/googleapis/cloud/kms/v1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	wrappb "google.golang.org/protobuf/types/known/wrapperspb"
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

// pemCapablePQCPublicKey populates response for a PQC key that still supports
// PEM (the ML-DSA family): the initial PEM request succeeds. Regular ML-DSA keys
// are fully served by this response, while external-mu keys are additionally
// re-fetched in NIST_PQC to obtain the raw public key bytes (see externalMuPublicKey).
func (s *mockKMS) pemCapablePQCPublicKey(req *kmspb.GetPublicKeyRequest, response *kmspb.PublicKey, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) *kmspb.PublicKey {
	response.Algorithm = algorithm
	response.PublicKeyFormat = kmspb.PublicKey_PEM
	if req.GetPublicKeyFormat() == kmspb.PublicKey_NIST_PQC {
		response.PublicKeyFormat = kmspb.PublicKey_NIST_PQC
	}
	return response
}

// nistPQCOnlyPublicKey populates response for a PQC key that only supports
// NIST_PQC (the SLH-DSA family): PEM requests are rejected, forcing the signer
// to retry in NIST_PQC.
func (s *mockKMS) nistPQCOnlyPublicKey(req *kmspb.GetPublicKeyRequest, response *kmspb.PublicKey, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (*kmspb.PublicKey, error) {
	if req.GetPublicKeyFormat() != kmspb.PublicKey_NIST_PQC {
		return nil, status.Error(codes.InvalidArgument, "Only NIST_PQC format is supported for PQC algorithms.")
	}
	response.Algorithm = algorithm
	response.PublicKeyFormat = kmspb.PublicKey_NIST_PQC
	return response, nil
}

// externalMuPublicKey populates response for an external-mu ML-DSA key. Like the
// rest of the ML-DSA family it supports PEM and is re-fetched in NIST_PQC, but
// the signer also needs the raw public key bytes to compute μ, so it returns a
// correctly-sized key with a matching checksum.
func (s *mockKMS) externalMuPublicKey(req *kmspb.GetPublicKeyRequest, response *kmspb.PublicKey, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, publicKeyBytes []byte) *kmspb.PublicKey {
	response = s.pemCapablePQCPublicKey(req, response, algorithm)
	response.PublicKey = &kmspb.ChecksummedData{
		Data:           publicKeyBytes,
		Crc32CChecksum: &wrappb.Int64Value{Value: computeChecksum(publicKeyBytes)},
	}
	return response
}

// classicalVerifierPublicKey populates response with the real, parseable public key material for a
// verifier test key, keyed by name. It returns false if the key name is not a verifier classical key.
func (s *mockKMS) classicalVerifierPublicKey(response *kmspb.PublicKey, keyName string) (*kmspb.PublicKey, bool) {
	testKey, ok := verifierClassicalKeys[keyName]
	if !ok {
		return response, false
	}
	response.Algorithm = testKey.algorithm
	response.PublicKey = &kmspb.ChecksummedData{
		Data:           testKey.pemPublicKey,
		Crc32CChecksum: &wrappb.Int64Value{Value: computeChecksum(testKey.pemPublicKey)},
	}
	return response, true
}

// pqcVerifierPublicKey populates response with the raw public key material for a post-quantum
// verifier test key, keyed by name. SLH-DSA keys (nistPQCOnly) reject the initial PEM request; for
// ML-DSA keys, because we do not yet have OSS PEM parsing logic, we leave the default PEM
// response unchanged and supply the real public key bytes only in the NIST_PQC response.
// It returns false if the key name is not a verifier PQC key.
func (s *mockKMS) pqcVerifierPublicKey(req *kmspb.GetPublicKeyRequest, response *kmspb.PublicKey) (*kmspb.PublicKey, bool, error) {
	testKey, ok := verifierPQCKeys[req.GetName()]
	if !ok {
		return response, false, nil
	}
	if testKey.nistPQCOnly && req.GetPublicKeyFormat() != kmspb.PublicKey_NIST_PQC {
		return nil, true, status.Error(codes.InvalidArgument, "Only NIST_PQC format is supported for PQC algorithms.")
	}
	response.Algorithm = testKey.algorithm
	if req.GetPublicKeyFormat() == kmspb.PublicKey_NIST_PQC {
		response.PublicKey = &kmspb.ChecksummedData{
			Data:           testKey.rawPublicKey,
			Crc32CChecksum: &wrappb.Int64Value{Value: computeChecksum(testKey.rawPublicKey)},
		}
	}
	return response, true, nil
}

func (s *mockKMS) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	s.getPublicKeyFormatRequests = append(s.getPublicKeyFormatRequests, req.GetPublicKeyFormat())
	response := &kmspb.PublicKey{}
	response.Name = req.GetName()
	response.ProtectionLevel = kmspb.ProtectionLevel_SOFTWARE // Default protection level.
	response.PublicKeyFormat = req.GetPublicKeyFormat()

	publicKeyData := []byte("pem")
	publicKeyCrc32c := computeChecksum(publicKeyData)
	response.PublicKey = &kmspb.ChecksummedData{
		Data:           publicKeyData,
		Crc32CChecksum: &wrappb.Int64Value{Value: publicKeyCrc32c},
	}

	if resp, ok := s.classicalVerifierPublicKey(response, req.GetName()); ok {
		return resp, nil
	}
	if resp, ok, err := s.pqcVerifierPublicKey(req, response); ok {
		return resp, err
	}

	switch req.GetName() {
	case signKeyNameRequiresData1:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case signKeyNameRequiresData2:
		response.ProtectionLevel = kmspb.ProtectionLevel_EXTERNAL
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256
		return response, nil
	case signKeyNameRequiresDigest:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256
		return response, nil
	case signKeyNameErrorGetPublicKey:
		return nil, status.Error(codes.Internal, "Internal error")
	case signKeyNameErrorAsymmetricSign:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case signKeyNameErrorCRC32C:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case signKeyNameErrorCRC32CNotVerified:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case signKeyNameErrorWrongKeyName:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case signKeyNameErrorUnsupportedAlgorithm:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256
		return response, nil
	case signKeyNameErrorChecksumMismatchGetPublicKey:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		response.PublicKey.Crc32CChecksum.Value = 1
		return response, nil
	case signKeyNameErrorWrongKeyNameGetPublicKey:
		response.Name = "wrong key name"
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048
		return response, nil
	case signKeyNameMLDSA44:
		return s.pemCapablePQCPublicKey(req, response, kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44), nil
	case signKeyNameMLDSA65:
		return s.pemCapablePQCPublicKey(req, response, kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65), nil
	case signKeyNameMLDSA87:
		return s.pemCapablePQCPublicKey(req, response, kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87), nil
	case signKeyNamePureSLHDSA:
		return s.nistPQCOnlyPublicKey(req, response, kmspb.CryptoKeyVersion_PQ_SIGN_SLH_DSA_SHA2_128S)
	case signKeyNameHashSLHDSA:
		return s.nistPQCOnlyPublicKey(req, response, kmspb.CryptoKeyVersion_PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256)
	case signKeyNameMLDSA44ExternalMu:
		return s.externalMuPublicKey(req, response, kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44_EXTERNAL_MU, mldsaTestPublicKey(mldsa44PublicKeyBytes)), nil
	case signKeyNameMLDSA65ExternalMu:
		return s.externalMuPublicKey(req, response, kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU, mldsaTestPublicKey(mldsa65PublicKeyBytes)), nil
	case signKeyNameMLDSA87ExternalMu:
		return s.externalMuPublicKey(req, response, kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87_EXTERNAL_MU, mldsaTestPublicKey(mldsa87PublicKeyBytes)), nil
	case signKeyNameMLDSAExternalMuInvalidKey:
		// A wrong-sized public key makes the signer fail the size check at construction.
		return s.externalMuPublicKey(req, response, kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU, mldsaTestPublicKey(mldsa65PublicKeyBytes-1)), nil
	case signKeyNameErrorChecksumMismatchGetPublicKeyPQC:
		response, err := s.nistPQCOnlyPublicKey(req, response, kmspb.CryptoKeyVersion_PQ_SIGN_SLH_DSA_SHA2_128S)
		if err != nil {
			return nil, err
		}
		response.PublicKey.Crc32CChecksum.Value = 1
		return response, nil
	case verifyKeyNameErrorGetPublicKey:
		return nil, status.Error(codes.Internal, "Internal error")
	case verifyKeyNameErrorUnsupportedAlgorithm:
		response.Algorithm = kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256
		return response, nil
	case verifyKeyNameErrorChecksumMismatch:
		response, _ = s.classicalVerifierPublicKey(response, verifyKeyNameECP256)
		response.PublicKey.Crc32CChecksum.Value = 1
		return response, nil
	case verifyKeyNameErrorWrongKeyName:
		response, _ = s.classicalVerifierPublicKey(response, verifyKeyNameECP256)
		response.Name = "wrong key name"
		return response, nil
	default:
		return nil, status.Error(codes.NotFound, "Key not found")
	}
}

func (s *mockKMS) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	s.lastAsymmetricSignRequest = req
	if req.GetName() == signKeyNameErrorAsymmetricSign {
		return nil, status.Error(codes.Internal, "Internal error")
	}
	response := &kmspb.AsymmetricSignResponse{
		Name: req.GetName(),
	}
	if req.GetDigest() != nil {
		response.VerifiedDigestCrc32C = true
		response.Signature = signatureForKey([]byte(signDigest), req.GetName())
	} else {
		response.VerifiedDataCrc32C = true
		response.Signature = signatureForKey(req.GetData(), req.GetName())
	}
	response.SignatureCrc32C = &wrappb.Int64Value{Value: computeChecksum(response.GetSignature())}
	switch req.GetName() {
	case signKeyNameErrorWrongKeyName:
		response.Name = "wrong key name"
	case signKeyNameErrorCRC32C:
		response.SignatureCrc32C = &wrappb.Int64Value{Value: 1}
	case signKeyNameErrorCRC32CNotVerified:
		response.VerifiedDataCrc32C = false
		response.VerifiedDigestCrc32C = false
	}
	return response, nil
}
