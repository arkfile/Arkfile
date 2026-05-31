//go:build !windows

package main

import "syscall"

// daemonSysProcAttr returns POSIX process attributes to detach the daemon from the parent session.
func daemonSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}
