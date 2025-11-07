// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gob

import (
	"bytes"
	"testing"
)

func FuzzGobDecode(f *testing.F) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	enc.Encode(map[string]int{"test": 42})
	f.Add(buf.Bytes())
	
	f.Fuzz(func(t *testing.T, data []byte) {
		dec := NewDecoder(bytes.NewReader(data))
		var result interface{}
		dec.Decode(&result)
	})
}
