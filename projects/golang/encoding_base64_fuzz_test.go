// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package base64

import (
	"testing"
)

func FuzzBase64Decode(f *testing.F) {
	f.Add([]byte("SGVsbG8gV29ybGQ="))
	
	f.Fuzz(func(t *testing.T, data []byte) {
		// Try standard encoding
		StdEncoding.DecodeString(string(data))
		
		// Try URL encoding
		URLEncoding.DecodeString(string(data))
		
		// Try raw encodings
		RawStdEncoding.DecodeString(string(data))
		RawURLEncoding.DecodeString(string(data))
	})
}
