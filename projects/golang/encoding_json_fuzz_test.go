// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package json

import (
	"testing"
)

func FuzzJSONDecode(f *testing.F) {
	f.Add([]byte(`{"key": "value"}`))
	f.Add([]byte(`[1, 2, 3]`))
	
	f.Fuzz(func(t *testing.T, data []byte) {
		var result interface{}
		Unmarshal(data, &result)
	})
}
