//go:build !linux

package crypto

import "fmt"

// prctlDisableCoredump is a no-op on non-Linux systems.
func prctlDisableCoredump() error {
	return nil
}

// mLockMemory is a best-effort warning/no-op on non-Linux systems.
func mLockMemory(key []byte) error {
	return fmt.Errorf("mlock not supported natively on this platform")
}

// mAdviseDontDump is a no-op on non-Linux systems.
func mAdviseDontDump(key []byte) error {
	return nil
}

// mUnlockMemory is a no-op on non-Linux systems.
func mUnlockMemory(key []byte) error {
	return nil
}
