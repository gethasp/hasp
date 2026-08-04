//go:build unix

package runtime

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

var (
	daemonFlock    = syscall.Flock
	statSocketFile = os.Stat
)

// acquireDaemonLock takes the exclusive, non-blocking advisory lock that makes
// `hasp daemon serve` a singleton, and returns a func that drops it.
//
// The lock lives in the kernel, attached to the open fd, so it is released on
// every exit path including SIGKILL and panic. That is why it replaces the
// O_EXCL write of daemon.http.port as the de-facto singleton guard: a leftover
// file survives a hard kill and wedges the next start, an flock does not.
func acquireDaemonLock(path string) (func(), error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open daemon lock: %w", err)
	}
	if err := daemonFlock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errDaemonAlreadyRunning
		}
		return nil, fmt.Errorf("lock daemon: %w", err)
	}
	return func() {
		_ = daemonFlock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

// socketIdentity encodes the (device, inode) pair of the socket a daemon bound.
// The daemon re-stats its socket path periodically and compares: if the path now
// resolves elsewhere, some other process unlinked us and took the name, and we
// are serving an unreachable inode.
//
// It is a formatted string rather than a struct of integers because Stat_t's
// Dev and Ino widths differ per platform, so any fixed integer type needs a
// conversion that is redundant on some target and required on another.
type socketIdentity string

func statSocketIdentity(path string) (socketIdentity, error) {
	info, err := statSocketFile(path)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("stat socket: unexpected stat type")
	}
	return socketIdentity(fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)), nil
}
