// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdsa_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"
)

func FuzzEcdsaSign(f *testing.F) {
	f.Add([]byte("0123456789abcdef0123456789abcdef0123456789abcdef"), []byte("hash data here"), uint8(0))
	
	f.Fuzz(func(t *testing.T, data, hash []byte, curveIdx uint8) {
		if len(data) < 5 {
			return
		}
		
		curves := []elliptic.Curve{
			elliptic.P224(),
			elliptic.P256(),
			elliptic.P384(),
			elliptic.P521(),
		}
		
		c := curves[int(curveIdx)%len(curves)]
		priv, err := ecdsa.GenerateKey(c, bytes.NewReader(data))
		if err != nil {
			return
		}
		
		r, s, err := ecdsa.Sign(bytes.NewReader(data[len(data)/2:]), priv, hash)
		if err != nil {
			return
		}
		
		// Verify the signature
		if !ecdsa.Verify(&priv.PublicKey, hash, r, s) {
			t.Errorf("signature verification failed")
		}
	})
}

func FuzzEcdsaVerify(f *testing.F) {
	f.Add([]byte("0123456789abcdef0123456789abcdef0123456789abcdef"), []byte("hash"), "12345", "67890", uint8(0))
	
	f.Fuzz(func(t *testing.T, data, hash []byte, rStr, sStr string, curveIdx uint8) {
		if len(data) < 5 {
			return
		}
		
		curves := []elliptic.Curve{
			elliptic.P224(),
			elliptic.P256(),
			elliptic.P384(),
			elliptic.P521(),
		}
		
		c := curves[int(curveIdx)%len(curves)]
		priv, err := ecdsa.GenerateKey(c, bytes.NewReader(data))
		if err != nil {
			return
		}
		
		r, ok := new(big.Int).SetString(rStr, 10)
		if !ok {
			return
		}
		s, ok := new(big.Int).SetString(sStr, 10)
		if !ok {
			return
		}
		
		ecdsa.Verify(&priv.PublicKey, hash, r, s)
	})
}

