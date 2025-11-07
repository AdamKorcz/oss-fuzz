// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package base32

import (
	"bytes"
	"testing"
)

func FuzzBase32Decode(f *testing.F) {
	f.Add([]byte("MFRGG==="), "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
	
	f.Fuzz(func(t *testing.T, data []byte, alphabet string) {
		if len(alphabet) != 32 {
			return
		}
		
		enc := NewEncoding(alphabet)
		dec := NewDecoder(enc, bytes.NewReader(data))
		buf := make([]byte, enc.DecodedLen(len(data)))
		dec.Read(buf)
	})
}
