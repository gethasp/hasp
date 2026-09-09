//go:build darwin || linux

package runner

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

var flockRunDir = syscall.Flock

func tryLockRunDir(path string) (func(), error) {
	file, err := os.OpenFile(filepath.Join(path, ".active"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := flockRunDir(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, nil
		}
		return nil, err
	}
	return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
}
