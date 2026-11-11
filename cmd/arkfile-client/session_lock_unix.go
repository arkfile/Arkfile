//go:build !windows

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockSessionFile takes an exclusive lock that serializes refresh across
// arkfile-client processes sharing one session file.
func lockSessionFile(sessionPath string) (func(), error) {
	lock, err := os.OpenFile(sessionPath+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return func() {
		_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		_ = lock.Close()
	}, nil
}
