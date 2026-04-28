//go:build darwin

package runtime

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// xucred mirrors the xucred struct used by LOCAL_PEERCRED on Darwin.
// From <sys/ucred.h>:
//
//	struct xucred {
//	    u_int   cr_version;   /* structure layout version */
//	    uid_t   cr_uid;       /* effective user id */
//	    ...
//	};
//
// We only need cr_version (uint32) and cr_uid (uint32).
type xucred struct {
	Version uint32
	UID     uint32
	// remainder of the struct is not needed; we size the buffer generously.
	_pad [32]byte
}

const (
	// SOL_LOCAL is the socket-level for LOCAL_PEERCRED / LOCAL_PEERPID on Darwin.
	solLocal      = 0
	localPeerCred = 0x001
	localPeerPID  = 0x002
)

// realPeerUID returns the effective UID of the peer connected on conn using
// LOCAL_PEERCRED (Darwin). conn must be a *net.UnixConn; any other type is
// rejected fail-closed.
//
// Strategy: stdlib-only, no external deps. We use SyscallConn to get the fd,
// then call syscall.Getsockopt directly with the raw LOCAL_PEERCRED option and
// parse the xucred struct manually. This avoids golang.org/x/sys/unix which
// would be the first external dependency in this module.
func realPeerUID(conn net.Conn) (uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("peer credential lookup: not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("peer credential lookup: SyscallConn: %w", err)
	}
	var uid uint32
	var credErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		var cred xucred
		size := uint32(unsafe.Sizeof(cred))
		// syscall.Getsockopt is not exported in a form that accepts a raw
		// pointer, so we call the underlying syscall directly.
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(solLocal),
			uintptr(localPeerCred),
			uintptr(unsafe.Pointer(&cred)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			credErr = fmt.Errorf("peer credential lookup: getsockopt LOCAL_PEERCRED: %w", errno)
			return
		}
		uid = cred.UID
	})
	if ctrlErr != nil {
		return 0, fmt.Errorf("peer credential lookup: control: %w", ctrlErr)
	}
	if credErr != nil {
		return 0, credErr
	}
	return uid, nil
}

// realPeerPID returns the PID of the peer connected on conn using
// LOCAL_PEERPID (Darwin). conn must be a *net.UnixConn; any other type is
// rejected fail-closed.
func realPeerPID(conn net.Conn) (uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("peer credential lookup: not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("peer credential lookup: SyscallConn: %w", err)
	}
	var pid uint32
	var pidErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		var value uint32
		size := uint32(unsafe.Sizeof(value))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(solLocal),
			uintptr(localPeerPID),
			uintptr(unsafe.Pointer(&value)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			pidErr = fmt.Errorf("peer credential lookup: getsockopt LOCAL_PEERPID: %w", errno)
			return
		}
		pid = value
	})
	if ctrlErr != nil {
		return 0, fmt.Errorf("peer credential lookup: control: %w", ctrlErr)
	}
	if pidErr != nil {
		return 0, pidErr
	}
	return pid, nil
}
