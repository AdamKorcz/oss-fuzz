// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes_test

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func FuzzAesCtrStream(f *testing.F) {
	f.Add([]byte("0123456789abcdef"), []byte("0123456789abcdef"), []byte("test data here!!"))
	
	f.Fuzz(func(t *testing.T, key, iv, plaintext []byte) {
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return
		}
		if len(iv) != aes.BlockSize {
			return
		}
		
		block, err := aes.NewCipher(key)
		if err != nil {
			return
		}
		
		ciphertext := make([]byte, len(plaintext))
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(ciphertext, plaintext)
		
		// Decrypt and verify
		stream = cipher.NewCTR(block, iv)
		decrypted := make([]byte, len(ciphertext))
		stream.XORKeyStream(decrypted, ciphertext)
		
		if string(decrypted) != string(plaintext) {
			t.Errorf("CTR decryption failed")
		}
	})
}

func FuzzAesOfbStream(f *testing.F) {
	f.Add([]byte("0123456789abcdef"), []byte("0123456789abcdef"), []byte("test data here!!"))
	
	f.Fuzz(func(t *testing.T, key, iv, plaintext []byte) {
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return
		}
		if len(iv) != aes.BlockSize {
			return
		}
		
		block, err := aes.NewCipher(key)
		if err != nil {
			return
		}
		
		ciphertext := make([]byte, len(plaintext))
		stream := cipher.NewOFB(block, iv)
		stream.XORKeyStream(ciphertext, plaintext)
		
		// Decrypt and verify
		stream = cipher.NewOFB(block, iv)
		decrypted := make([]byte, len(ciphertext))
		stream.XORKeyStream(decrypted, ciphertext)
		
		if string(decrypted) != string(plaintext) {
			t.Errorf("OFB decryption failed")
		}
	})
}

func FuzzAesCfbEncrypter(f *testing.F) {
	f.Add([]byte("0123456789abcdef"), []byte("0123456789abcdef"), []byte("test data here!!"))
	
	f.Fuzz(func(t *testing.T, key, iv, plaintext []byte) {
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return
		}
		if len(iv) != aes.BlockSize {
			return
		}
		
		block, err := aes.NewCipher(key)
		if err != nil {
			return
		}
		
		ciphertext := make([]byte, len(plaintext))
		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(ciphertext, plaintext)
		
		// Decrypt and verify
		decrypted := make([]byte, len(ciphertext))
		stream = cipher.NewCFBDecrypter(block, iv)
		stream.XORKeyStream(decrypted, ciphertext)
		
		if string(decrypted) != string(plaintext) {
			t.Errorf("CFB decryption failed")
		}
	})
}

func FuzzAesCfbDecrypter(f *testing.F) {
	f.Add([]byte("0123456789abcdef"), []byte("0123456789abcdef"), []byte("encrypted data!!"))
	
	f.Fuzz(func(t *testing.T, key, iv, ciphertext []byte) {
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return
		}
		if len(iv) != aes.BlockSize {
			return
		}
		
		block, err := aes.NewCipher(key)
		if err != nil {
			return
		}
		
		plaintext := make([]byte, len(ciphertext))
		stream := cipher.NewCFBDecrypter(block, iv)
		stream.XORKeyStream(plaintext, ciphertext)
	})
}
