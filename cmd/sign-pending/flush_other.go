//go:build !linux

package main

import "os"

func flushInput(*os.File) {}
