// Copyright 2025 Google LLC
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

import "hash/crc32"

// crc32cTable is used to compute checksums. It is defined as a package level variable to avoid
// re-computation on every CRC calculation.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// computeChecksum returns the checksum that corresponds to the input value as an int64.
func computeChecksum(value []byte) int64 {
	return int64(crc32.Checksum(value, crc32cTable))
}
