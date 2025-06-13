//go:build !js && !wasm
// +build !js,!wasm

package main

import (
	"testing"
)

// Placeholder test file to satisfy Go's testing requirements
// The actual client package contains WebAssembly code that can't be tested
// in the standard Go testing environment due to build constraints.

func TestPlaceholder(t *testing.T) {
	// This test exists only to prevent build errors when running tests
	// on the client package, which contains WebAssembly-specific code.
	t.Skip("Client package contains WebAssembly code - skipping in standard test environment")
}
