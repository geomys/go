// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build wasm

package drbg

import (
	"crypto/internal/fips140"
	"crypto/internal/fips140deps/godebug"
	"crypto/internal/sysrand"
)

var fips140wasmentropy = godebug.New("#fips140wasmentropy")

func readFromEntropy(b []byte) {
	// We have not yet figured out how to get the internal Entropy Source
	// working in Wasm. For now, to make it possible to test the rest of FIPS
	// 140-3 mode, use an explicit opt-in to run in a non-compliant mode.
	// This is not intended for production use.
	if fips140wasmentropy.Value() == "bypass" {
		fips140.RecordNonApproved()
		sysrand.Read(b)
		return
	}
	panic("FIPS-140 entropy generation is not supported on Wasm")
}
