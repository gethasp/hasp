//go:build darwin

package runtime

import (
	"fmt"

	"golang.org/x/sys/unix"
)

var sysctlKinfoProcFn = unix.SysctlKinfoProc

// realProcessIdentity returns a token derived from the process start time as
// reported by kern.proc.pid. The token is only a stale-binding check; callers
// must not treat PID+starttime as an authorization capability.
func realProcessIdentity(pid int) (string, error) {
	if pid <= 0 {
		return "", nil
	}
	kp, err := sysctlKinfoProcFn("kern.proc.pid", pid)
	if err != nil || kp == nil {
		return "", nil
	}
	return fmt.Sprintf("%d.%06d", kp.Proc.P_starttime.Sec, kp.Proc.P_starttime.Usec), nil
}

func realProcessParentPID(pid int) (int, error) {
	if pid <= 0 {
		return 0, nil
	}
	kp, err := sysctlKinfoProcFn("kern.proc.pid", pid)
	if err != nil {
		return 0, fmt.Errorf("resolve parent pid: %w", err)
	}
	if kp == nil {
		return 0, nil
	}
	return int(kp.Eproc.Ppid), nil
}
