// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package elf

import (
	"os"
	"testing"
)

func FuzzElfOpen(f *testing.F) {
	f.Add([]byte("\x7fELF"))
	
	f.Fuzz(func(t *testing.T, data []byte) {
		tmpfile, err := os.CreateTemp("", "fuzz-elf-*")
		if err != nil {
			return
		}
		defer os.Remove(tmpfile.Name())
		defer tmpfile.Close()
		
		_, err = tmpfile.Write(data)
		if err != nil {
			return
		}
		tmpfile.Close()
		
		elfFile, err := Open(tmpfile.Name())
		if err != nil {
			return
		}
		defer elfFile.Close()
		
		// Try to read some sections
		_ = elfFile.Sections
		_, _ = elfFile.Symbols()
	})
}
