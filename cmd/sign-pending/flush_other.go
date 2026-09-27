//go:build !(linux && (amd64 || arm64 || riscv64))

package main

import "os"

func flushInput(*os.File) {}
