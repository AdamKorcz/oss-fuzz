// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package multipart_test

import (
	"bytes"
	"io"
	"mime/multipart"
	"testing"
)

func FuzzReader(f *testing.F) {
	boundary := "----WebKitFormBoundary7MA4YWxkTrZu0gW"
	sample := []byte("------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" +
		"Content-Disposition: form-data; name=\"field1\"\r\n\r\n" +
		"value1\r\n" +
		"------WebKitFormBoundary7MA4YWxkTrZu0gW--")
	f.Add(sample, boundary)
	
	f.Fuzz(func(t *testing.T, data []byte, boundary string) {
		if boundary == "" {
			return
		}
		
		r := multipart.NewReader(bytes.NewReader(data), boundary)
		
		// Try to read all parts
		for {
			part, err := r.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return
			}
			
			// Read part data
			io.Copy(io.Discard, part)
			part.Close()
		}
	})
}

func FuzzReadForm(f *testing.F) {
	boundary := "----WebKitFormBoundary7MA4YWxkTrZu0gW"
	sample := []byte("------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" +
		"Content-Disposition: form-data; name=\"field1\"\r\n\r\n" +
		"value1\r\n" +
		"------WebKitFormBoundary7MA4YWxkTrZu0gW--")
	f.Add(sample, boundary)
	
	f.Fuzz(func(t *testing.T, data []byte, boundary string) {
		if boundary == "" {
			return
		}
		
		r := multipart.NewReader(bytes.NewReader(data), boundary)
		form, err := r.ReadForm(1 << 20) // 1MB max
		if err != nil {
			return
		}
		
		if form != nil {
			form.RemoveAll()
		}
	})
}
