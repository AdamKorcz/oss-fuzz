// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tiff_test

import (
	"bytes"
	"image/tiff"
	"testing"
)

func FuzzDecode(f *testing.F) {
	// TIFF header (little-endian)
	f.Add([]byte{0x49, 0x49, 0x2A, 0x00})
	// TIFF header (big-endian)
	f.Add([]byte{0x4D, 0x4D, 0x00, 0x2A})
	
	f.Fuzz(func(t *testing.T, data []byte) {
		// Try to decode config
		config, err := tiff.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			return
		}
		
		// Limit image size to prevent OOM
		if config.Width*config.Height > 1000000 {
			return
		}
		
		// Try to decode the full image
		img, err := tiff.Decode(bytes.NewReader(data))
		if err != nil {
			return
		}
		_ = img
	})
}
