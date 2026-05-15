//go:build unix && !linux && !darwin

package runtime

import "fmt"

func realProcessParentPID(pid int) (int, error) {
	if pid <= 0 {
		return 0, nil
	}
	return 0, fmt.Errorf("resolve parent pid: unsupported platform")
}
