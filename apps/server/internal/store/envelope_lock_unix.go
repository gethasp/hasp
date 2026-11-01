//go:build darwin || linux || freebsd || openbsd || netbsd

package store

import (
	"fmt"
	"os"
	"syscall"
)

func lockEnvelopeReplacement(path string) (func(), error) {
	file, err := os.OpenFile(path+".write.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open vault replacement lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock vault replacement: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}
