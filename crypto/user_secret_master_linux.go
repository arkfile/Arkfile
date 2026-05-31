//go:build linux

package crypto

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// prctlDisableCoredump disables core dumps for the current process on Linux.
func prctlDisableCoredump() error {
	_, _, sysErr := syscall.Syscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0)
	if sysErr != 0 {
		return sysErr
	}
	return nil
}

// mLockMemory invokes native UNIX memory locking.
func mLockMemory(key []byte) error {
	return unix.Mlock(key)
}

// mAdviseDontDump excludes memory pages from core dumps.
func mAdviseDontDump(key []byte) error {
	return unix.Madvise(key, unix.MADV_DONTDUMP)
}

// mUnlockMemory releases a locked memory page.
func mUnlockMemory(key []byte) error {
	return unix.Munlock(key)
}
