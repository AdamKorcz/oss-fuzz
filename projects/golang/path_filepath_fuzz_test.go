// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filepath_test

import (
	"path/filepath"
	"testing"
)

func FuzzGlob(f *testing.F) {
	f.Add("*.go")
	f.Add("test/**/file.txt")
	f.Add("/tmp/*/test")
	
	f.Fuzz(func(t *testing.T, pattern string) {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return
		}
		_ = matches
	})
}

func FuzzMatch(f *testing.F) {
	f.Add("*.go", "test.go")
	f.Add("test/*", "test/file.txt")
	
	f.Fuzz(func(t *testing.T, pattern, name string) {
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			return
		}
		_ = matched
	})
}
