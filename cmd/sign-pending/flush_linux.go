//go:build linux

package main

import (
	"os"
	"syscall"
)

// flushInput discards typed-ahead terminal input (tcflush TCIFLUSH), so a keystroke made
// while the approval screen was still loading cannot answer the prompt.
func flushInput(f *os.File) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TCFLSH, syscall.TCIFLUSH)
}
