//go:build linux

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

// renameNoReplace moves oldPath to newPath only when newPath does not exist.
// Filesystems without RENAME_NOREPLACE (NFS, some FUSE mounts) fall back to
// a hard link, which also refuses an existing destination.
func renameNoReplace(oldPath, newPath string) error {
	err := unix.Renameat2(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, unix.RENAME_NOREPLACE)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EEXIST) {
		return errDestinationExists
	}
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		return linkNoReplace(oldPath, newPath)
	}
	return err
}
