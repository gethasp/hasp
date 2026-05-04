//go:build darwin || linux

package app

import (
	"os"
	"syscall"
)

func openWriteEnvFile(path string, flag int, perm os.FileMode) (writeEnvFile, error) {
	return os.OpenFile(path, flag|syscall.O_NOFOLLOW, perm)
}
