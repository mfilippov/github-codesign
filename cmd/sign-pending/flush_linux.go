//go:build linux && (amd64 || arm64 || riscv64)

package main

import (
	"os"
	"syscall"
)

// TCFLSH/TCIFLUSH from asm-generic ioctls; package syscall defines TCFLSH only on some
// architectures.
const (
	tcflsh   = 0x540B
	tciflush = 0
)

// flushInput discards typed-ahead terminal input (tcflush TCIFLUSH), so a keystroke made
// while the approval screen was still loading cannot answer the prompt.
func flushInput(f *os.File) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tcflsh, tciflush)
}
