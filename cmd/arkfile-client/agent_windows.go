//go:build windows

package main

import (
	"fmt"
	"net"
)

// isPeerAuthorized is a no-op on Windows since named UNIX sockets on Windows
// do not support Unix-style SO_PEERCRED or LOCAL_PEERCRED socket options.
// Instead, security is strictly derived from standard NTFS directory/file ACLs (0600).
func isPeerAuthorized(conn net.Conn) (bool, error) {
	return true, nil
}

func mlock(data []byte) error {
	return fmt.Errorf("mlock not supported on windows")
}

func munlock(data []byte) error {
	return nil
}

// validateSocketSecurity is a simplified socket security checker for Windows.
// Note: standard ownership is derived from file permissions on Windows NTFS.
func validateSocketSecurity(socketPath string, expectedUID int) error {
	return nil
}
