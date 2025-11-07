// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dsa

import (
	"bytes"
	"math/big"
	"testing"
)

func FuzzDsaVerify(f *testing.F) {
	f.Add([]byte("0123456789abcdef0123456789abcdef"), []byte("0123456789abcdef"), []byte("hash data"), "12345", "67890", uint8(0))
	
	f.Fuzz(func(t *testing.T, data1, data2, data3 []byte, s1, s2 string, s uint8) {
		var priv PrivateKey
		params := &priv.Parameters
		sizes := []ParameterSizes{
			L1024N160,
			L2048N224,
			L2048N256,
			L3072N256,
		}
		
		bi1, ok := new(big.Int).SetString(s1, 10)
		if !ok {
			return
		}
		bi2, ok := new(big.Int).SetString(s2, 10)
		if !ok {
			return
		}
		
		err := GenerateParameters(params, bytes.NewReader(data1), sizes[int(s)%len(sizes)])
		if err != nil {
			return
		}
		err = GenerateKey(&priv, bytes.NewReader(data2))
		if err != nil {
			return
		}
		Verify(&priv.PublicKey, data3, bi1, bi2)
	})
}

func FuzzDsaSign(f *testing.F) {
	f.Add([]byte("0123456789abcdef0123456789abcdef"), []byte("0123456789abcdef"), []byte("random"), []byte("hash"), uint8(0))
	
	f.Fuzz(func(t *testing.T, data1, data2, data3, data4 []byte, s uint8) {
		var priv PrivateKey
		params := &priv.Parameters
		sizes := []ParameterSizes{
			L1024N160,
			L2048N224,
			L2048N256,
			L3072N256,
		}
		
		err := GenerateParameters(params, bytes.NewReader(data1), sizes[int(s)%len(sizes)])
		if err != nil {
			return
		}
		err = GenerateKey(&priv, bytes.NewReader(data2))
		if err != nil {
			return
		}
		Sign(bytes.NewReader(data3), &priv, data4)
	})
}
