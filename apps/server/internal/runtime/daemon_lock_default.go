//go:build !unix

package runtime

import (
	"errors"
	"fmt"
	"os"
)

// acquireDaemonLock has no advisory-lock implementation off unix. The daemon
// still starts; it just loses the singleton guarantee, same as before the lock
// existed.
func acquireDaemonLock(string) (func(), error) {
	return func() {}, nil
}

// socketIdentity stands in for the unix (device, inode) pair with the closest
// portable approximation: size plus modification time.
type socketIdentity string

func statSocketIdentity(path string) (socketIdentity, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info == nil {
		return "", errors.New("stat socket: no file info")
	}
	return socketIdentity(fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())), nil
}
