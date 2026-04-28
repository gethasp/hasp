//go:build linux

package runtime

import (
	"fmt"
	"net"
	"syscall"
)

// realPeerUID returns the effective UID of the peer connected on conn using
// SO_PEERCRED (Linux). conn must be a *net.UnixConn; any other type is
// rejected fail-closed.
func realPeerUID(conn net.Conn) (uint32, error) {
	cred, err := peerUcred(conn)
	if err != nil {
		return 0, err
	}
	return uint32(cred.Uid), nil
}

// realPeerPID returns the PID of the peer connected on conn using
// SO_PEERCRED (Linux). conn must be a *net.UnixConn; any other type is
// rejected fail-closed.
func realPeerPID(conn net.Conn) (uint32, error) {
	cred, err := peerUcred(conn)
	if err != nil {
		return 0, err
	}
	return uint32(cred.Pid), nil
}

func peerUcred(conn net.Conn) (*syscall.Ucred, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("peer credential lookup: not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("peer credential lookup: SyscallConn: %w", err)
	}
	var ucred *syscall.Ucred
	var credErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		ucred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if credErr != nil {
			credErr = fmt.Errorf("peer credential lookup: getsockopt SO_PEERCRED: %w", credErr)
		}
	})
	if ctrlErr != nil {
		return nil, fmt.Errorf("peer credential lookup: control: %w", ctrlErr)
	}
	if credErr != nil {
		return nil, credErr
	}
	return ucred, nil
}
