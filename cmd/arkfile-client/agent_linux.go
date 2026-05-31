//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

func mlock(data []byte) error {
	return syscall.Mlock(data)
}

func munlock(data []byte) error {
	return syscall.Munlock(data)
}

// validateSocketSecurity ensures socket is owned by current user with correct permissions
func validateSocketSecurity(socketPath string, expectedUID int) error {
	info, err := os.Stat(socketPath)
	if err != nil {
		return fmt.Errorf("failed to stat socket: %w", err)
	}

	// Check ownership (POSIX: works on Linux, FreeBSD, OpenBSD, Alpine)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("failed to get socket stat info")
	}

	if int(stat.Uid) != expectedUID {
		return fmt.Errorf("socket owner mismatch: expected UID %d, got %d", expectedUID, stat.Uid)
	}

	// Check permissions (must be exactly 0600)
	if info.Mode().Perm() != 0600 {
		return fmt.Errorf("insecure socket permissions: %o (expected 0600)", info.Mode().Perm())
	}

	return nil
}

// isPeerAuthorized retrieves the UID of the process connecting on the Unix socket
// using SO_PEERCRED, ensuring only the owner of the agent can make requests.
func isPeerAuthorized(conn net.Conn) (bool, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return false, fmt.Errorf("not a unix connection")
	}

	f, err := unixConn.File()
	if err != nil {
		return false, fmt.Errorf("failed to get connection file: %w", err)
	}
	defer f.Close()

	ucred, err := syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return false, fmt.Errorf("failed to get peer credentials: %w", err)
	}

	expectedUID := uint32(os.Getuid())
	if ucred.Uid != expectedUID {
		return false, fmt.Errorf("peer credentials mismatch: UID %d does not match running user UID %d", ucred.Uid, expectedUID)
	}

	return true, nil
}
