//go:build darwin

package runtime

import (
	"fmt"
	"syscall"
	"unsafe"
)

// realProcessIdentity returns a token derived from the start time
// (kp_proc.p_starttime) of pid as reported by sysctl kern.proc.pid.<pid>.
// The (pid, starttime) pair is unique for the lifetime of the kernel,
// so a changed starttime indicates pid reuse.
//
// Stdlib-only via syscall.Sysctl's underlying SYS___SYSCTL: the legacy
// kinfo_proc layout begins with extern_proc, whose p_starttime (struct
// timeval, 16 bytes on darwin/arm64 and amd64) sits at offset 8 from the
// start of kinfo_proc.
//
// On any failure, we return "" with no error so callers fall back to
// advisory ancestry-only checks rather than denying legitimate sessions.
func realProcessIdentity(pid int) (string, error) {
	if pid <= 0 {
		return "", nil
	}
	// CTL_KERN, KERN_PROC, KERN_PROC_PID, pid
	mib := [4]int32{1, 14, 1, int32(pid)}
	// kinfo_proc on darwin is 648 bytes; size generously to absorb future
	// growth without parsing the trailing fields.
	const kinfoBufLen = 1024
	var buf [kinfoBufLen]byte
	size := uintptr(kinfoBufLen)
	_, _, errno := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		4,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		0,
	)
	if errno != 0 || size < 24 {
		return "", nil
	}
	// p_starttime is at offset 8 within kinfo_proc.kp_proc:
	// struct timeval { __darwin_time_t tv_sec; __darwin_suseconds_t tv_usec; }
	// On darwin/amd64 and darwin/arm64 these are 8 + 4 (with 4 bytes of
	// padding) — total 16 bytes. We render the (sec, usec) pair as the token.
	sec := *(*int64)(unsafe.Pointer(&buf[8]))
	usec := *(*int32)(unsafe.Pointer(&buf[16]))
	return fmt.Sprintf("%d.%06d", sec, usec), nil
}
