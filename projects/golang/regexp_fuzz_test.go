// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package regexp_test

import (
	"regexp"
	"testing"
)

func FuzzCompile(f *testing.F) {
	f.Add(".*")
	f.Add("[a-z]+")
	f.Add("\\d{3}-\\d{4}")
	
	f.Fuzz(func(t *testing.T, pattern string) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return
		}
		
		// Test matching
		re.MatchString("test string")
		re.FindString("test string")
	})
}

func FuzzCompilePOSIX(f *testing.F) {
	f.Add(".*")
	f.Add("[[:alpha:]]+")
	
	f.Fuzz(func(t *testing.T, pattern string) {
		re, err := regexp.CompilePOSIX(pattern)
		if err != nil {
			return
		}
		
		re.MatchString("test string")
	})
}

func FuzzMatch(f *testing.F) {
	f.Add("a+b", "aaab")
	f.Add("\\d+", "12345")
	
	f.Fuzz(func(t *testing.T, pattern, text string) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return
		}
		
		// Various match operations
		re.MatchString(text)
		re.FindString(text)
		re.FindAllString(text, -1)
		re.FindStringIndex(text)
		re.FindStringSubmatch(text)
	})
}

func FuzzReplaceAll(f *testing.F) {
	f.Add("a+", "test aaa bbb", "X")
	
	f.Fuzz(func(t *testing.T, pattern, src, repl string) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return
		}
		
		_ = re.ReplaceAllString(src, repl)
		_ = re.ReplaceAllLiteralString(src, repl)
	})
}
