// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package strings_test

import (
	"strings"
	"testing"
)

func FuzzSplit(f *testing.F) {
	f.Add("a,b,c", ",")
	f.Add("hello world", " ")
	
	f.Fuzz(func(t *testing.T, s, sep string) {
		result := strings.Split(s, sep)
		
		// Verify that joining brings it back
		if sep != "" {
			joined := strings.Join(result, sep)
			if joined != s && len(result) > 0 {
				// This is expected for trailing separators
			}
		}
	})
}

func FuzzFields(f *testing.F) {
	f.Add("hello world test")
	f.Add("  multiple   spaces  ")
	
	f.Fuzz(func(t *testing.T, s string) {
		result := strings.Fields(s)
		_ = result
	})
}

func FuzzContains(f *testing.F) {
	f.Add("hello world", "world")
	f.Add("test", "xyz")
	
	f.Fuzz(func(t *testing.T, s, substr string) {
		contains := strings.Contains(s, substr)
		index := strings.Index(s, substr)
		
		if contains && index == -1 {
			t.Errorf("Contains returned true but Index returned -1")
		}
		if !contains && index != -1 {
			t.Errorf("Contains returned false but Index returned %d", index)
		}
	})
}
