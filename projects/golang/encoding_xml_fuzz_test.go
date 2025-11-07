// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xml

import (
	"testing"
)

func FuzzXMLDecode(f *testing.F) {
	f.Add([]byte(`<root><item>test</item></root>`))
	
	f.Fuzz(func(t *testing.T, data []byte) {
		var result interface{}
		Unmarshal(data, &result)
	})
}
