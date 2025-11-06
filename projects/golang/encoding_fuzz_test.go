// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encoding_test

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"testing"
)

func FuzzBase32Decode(f *testing.F) {
	f.Add([]byte("MFRGG==="), "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
	
	f.Fuzz(func(t *testing.T, data []byte, alphabet string) {
		if len(alphabet) != 32 {
			return
		}
		
		enc := base32.NewEncoding(alphabet)
		dec := base32.NewDecoder(enc, bytes.NewReader(data))
		buf := make([]byte, enc.DecodedLen(len(data)))
		dec.Read(buf)
	})
}

func FuzzBase64Decode(f *testing.F) {
	f.Add([]byte("SGVsbG8gV29ybGQ="))
	
	f.Fuzz(func(t *testing.T, data []byte) {
		// Try standard encoding
		base64.StdEncoding.DecodeString(string(data))
		
		// Try URL encoding
		base64.URLEncoding.DecodeString(string(data))
		
		// Try raw encodings
		base64.RawStdEncoding.DecodeString(string(data))
		base64.RawURLEncoding.DecodeString(string(data))
	})
}

func FuzzGobDecode(f *testing.F) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	enc.Encode(map[string]int{"test": 42})
	f.Add(buf.Bytes())
	
	f.Fuzz(func(t *testing.T, data []byte) {
		dec := gob.NewDecoder(bytes.NewReader(data))
		var result interface{}
		dec.Decode(&result)
	})
}

func FuzzJSONDecode(f *testing.F) {
	f.Add([]byte(`{"key": "value"}`))
	f.Add([]byte(`[1, 2, 3]`))
	
	f.Fuzz(func(t *testing.T, data []byte) {
		var result interface{}
		json.Unmarshal(data, &result)
	})
}

func FuzzXMLDecode(f *testing.F) {
	f.Add([]byte(`<root><item>test</item></root>`))
	
	f.Fuzz(func(t *testing.T, data []byte) {
		var result interface{}
		xml.Unmarshal(data, &result)
	})
}
