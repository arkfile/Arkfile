//go:build !linux

package main

// renameNoReplace moves oldPath to newPath only when newPath does not exist.
func renameNoReplace(oldPath, newPath string) error {
	return linkNoReplace(oldPath, newPath)
}
