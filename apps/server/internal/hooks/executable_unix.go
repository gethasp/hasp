//go:build unix

package hooks

import (
	"os"

	"golang.org/x/sys/unix"
)

func hookExecutable(path string, _ os.FileInfo) bool {
	return unix.Access(path, unix.X_OK) == nil
}
