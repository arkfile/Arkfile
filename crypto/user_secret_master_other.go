//go:build !linux

package crypto

import "fmt"

// allocSecretPage reports no dedicated page on non-Linux systems; the key stays on the heap.
func allocSecretPage() ([]byte, error) {
	return nil, nil
}

// freeSecretPage is a no-op on non-Linux systems.
func freeSecretPage(page []byte) error {
	return nil
}

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
