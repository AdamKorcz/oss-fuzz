// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package big

import (
	"testing"
)

func FuzzBigIntCmp(f *testing.F) {
	f.Add("12345", "67890")
	f.Add("-999", "1000")
	
	f.Fuzz(func(t *testing.T, s1, s2 string) {
		bi1, ok := new(Int).SetString(s1, 10)
		if !ok {
			return
		}
		bi2, ok := new(Int).SetString(s2, 10)
		if !ok {
			return
		}
		
		// Compare operations
		bi1.Cmp(bi2)
		
		// Arithmetic operations
		new(Int).Add(bi1, bi2)
		new(Int).Sub(bi1, bi2)
		new(Int).Mul(bi1, bi2)
		
		if bi2.Sign() != 0 {
			new(Int).Div(bi1, bi2)
			new(Int).Mod(bi1, bi2)
		}
	})
}

func FuzzBigFloatSetFloat64(f *testing.F) {
	f.Add(3.14159)
	f.Add(-999.999)
	
	f.Fuzz(func(t *testing.T, value float64) {
		bf := new(Float).SetFloat64(value)
		if bf == nil {
			return
		}
		
		// Convert back to float64
		f64, _ := bf.Float64()
		_ = f64
	})
}

func FuzzBigRatSetString(f *testing.F) {
	f.Add("1/2")
	f.Add("3.14")
	f.Add("-99/100")
	
	f.Fuzz(func(t *testing.T, input string) {
		r := new(Rat)
		_, ok := r.SetString(input)
		if !ok {
			return
		}
		
		// Convert to float
		f64, _ := r.Float64()
		_ = f64
		
		// Convert back to string
		_ = r.String()
	})
}

func FuzzBigIntSetString(f *testing.F) {
	f.Add("123456789", 10)
	f.Add("deadbeef", 16)
	f.Add("1010101", 2)
	
	f.Fuzz(func(t *testing.T, s string, base int) {
		if base < 2 || base > 36 {
			return
		}
		
		bi := new(Int)
		_, ok := bi.SetString(s, base)
		if !ok {
			return
		}
		
		// Convert to different bases
		_ = bi.Text(10)
		_ = bi.Text(16)
	})
}
