//go:build linux

package crypto

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// allocSecretPage maps one anonymous private page outside the Go heap.
func allocSecretPage() ([]byte, error) {
	return unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
}

// freeSecretPage unmaps a page returned by allocSecretPage.
func freeSecretPage(page []byte) error {
	return unix.Munmap(page)
}

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
