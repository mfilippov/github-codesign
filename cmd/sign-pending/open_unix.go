//go:build unix

package main

import (
	"os"
	"syscall"
)

// openNoFollow opens a file in the runner-writable spool without following symlinks and
// without blocking on FIFOs.
func openNoFollow(name string) (*os.File, error) {
	return os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
