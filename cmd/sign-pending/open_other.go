//go:build !unix

package main

import "os"

// Only for running tests on a development machine; the tool itself is Linux-only.
func openNoFollow(name string) (*os.File, error) {
	return os.Open(name)
}
