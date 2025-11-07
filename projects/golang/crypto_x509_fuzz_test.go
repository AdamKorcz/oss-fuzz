// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"encoding/pem"
	"testing"
)

func FuzzParseCertificate(f *testing.F) {
	// Add a minimal DER-encoded certificate structure
	f.Add([]byte{0x30, 0x82, 0x01, 0x00})
	
	f.Fuzz(func(t *testing.T, data []byte) {
		cert, err := ParseCertificate(data)
		if err != nil {
			return
		}
		_ = cert
	})
}

func FuzzParseCertificates(f *testing.F) {
	f.Add([]byte{0x30, 0x82, 0x01, 0x00})
	
	f.Fuzz(func(t *testing.T, data []byte) {
		certs, err := ParseCertificates(data)
		if err != nil {
			return
		}
		_ = certs
	})
}

func FuzzParsePKIXPublicKey(f *testing.F) {
	f.Add([]byte{0x30, 0x82, 0x01, 0x00})
	
	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := ParsePKIXPublicKey(data)
		if err != nil {
			return
		}
		_ = key
	})
}

func FuzzParseCRL(f *testing.F) {
	f.Add([]byte{0x30, 0x82, 0x01, 0x00})
	
	f.Fuzz(func(t *testing.T, data []byte) {
		crl, err := ParseCRL(data)
		if err != nil {
			return
		}
		_ = crl
	})
}

func FuzzParsePEMCertificate(f *testing.F) {
	sample := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU2T/MA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
-----END CERTIFICATE-----`
	f.Add([]byte(sample))
	
	f.Fuzz(func(t *testing.T, data []byte) {
		block, _ := pem.Decode(data)
		if block == nil {
			return
		}
		
		if block.Type == "CERTIFICATE" {
			ParseCertificate(block.Bytes)
		}
	})
}
