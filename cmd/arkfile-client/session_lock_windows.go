//go:build windows

package main

import (
	"errors"
	"os"
	"time"
)

const (
	sessionLockWait  = 30 * time.Second
	sessionLockStale = 2 * time.Minute
)

// lockSessionFile takes an exclusive lock that serializes refresh across
// arkfile-client processes sharing one session file. A lock file left by a
// crashed process is ignored once it is older than sessionLockStale.
func lockSessionFile(sessionPath string) (func(), error) {
	lockPath := sessionPath + ".lock"
	deadline := time.Now().Add(sessionLockWait)
	for {
		lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_ = lock.Close()
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > sessionLockStale {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("timed out waiting for the session lock")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
