package main

import (
	"fmt"
	"os"
	"testing"
)

// TestMain points HOME at a throwaway directory so no test reads or writes the
// developer's real session file, session lock, or agent socket.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "arkfile-client-test-home-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create test HOME: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("HOME", home); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set test HOME: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}
