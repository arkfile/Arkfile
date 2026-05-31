//go:build windows

package main

import "syscall"

// daemonSysProcAttr returns Windows process attributes to detach the daemon from the parent session.
// On Windows, Setsid does not exist, so we return standard SysProcAttr block.
func daemonSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}
