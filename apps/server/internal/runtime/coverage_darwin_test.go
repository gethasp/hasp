//go:build darwin

package runtime

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestDarwinPeerCredentialFailureBranches(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if _, err := realPeerUID(c1); err == nil {
		t.Fatal("expected non-unix UID error")
	}
	if _, err := realPeerPID(c1); err == nil {
		t.Fatal("expected non-unix PID error")
	}

	origConn := peercredSyscallConn
	origControl := peercredRawControl
	origSyscall := peercredSyscall6
	t.Cleanup(func() {
		peercredSyscallConn = origConn
		peercredRawControl = origControl
		peercredSyscall6 = origSyscall
	})

	peercredSyscallConn = func(*net.UnixConn) (syscall.RawConn, error) {
		return nil, errors.New("syscallconn")
	}
	if _, err := realPeerUID(&net.UnixConn{}); err == nil {
		t.Fatal("expected UID SyscallConn error")
	}
	if _, err := realPeerPID(&net.UnixConn{}); err == nil {
		t.Fatal("expected PID SyscallConn error")
	}

	peercredSyscallConn = func(*net.UnixConn) (syscall.RawConn, error) { return nil, nil }
	peercredRawControl = func(syscall.RawConn, func(uintptr)) error { return errors.New("control") }
	if _, err := realPeerUID(&net.UnixConn{}); err == nil {
		t.Fatal("expected UID control error")
	}
	if _, err := realPeerPID(&net.UnixConn{}); err == nil {
		t.Fatal("expected PID control error")
	}

	peercredRawControl = func(_ syscall.RawConn, fn func(uintptr)) error {
		fn(0)
		return nil
	}
	peercredSyscall6 = func(uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, syscall.EINVAL
	}
	if _, err := realPeerUID(&net.UnixConn{}); err == nil {
		t.Fatal("expected UID getsockopt error")
	}
	if _, err := realPeerPID(&net.UnixConn{}); err == nil {
		t.Fatal("expected PID getsockopt error")
	}
}

func TestDarwinProcessIdentityRejectsInvalidPID(t *testing.T) {
	if got, err := realProcessIdentity(0); err != nil || got != "" {
		t.Fatalf("realProcessIdentity(0) = %q, %v", got, err)
	}
}
