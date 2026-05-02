//go:build linux

package runtime

import (
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
)

func TestLinuxPeerCredentialBranches(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if _, err := realPeerUID(c1); err == nil {
		t.Fatal("expected non-unix UID error")
	}
	if _, err := realPeerPID(c1); err == nil {
		t.Fatal("expected non-unix PID error")
	}

	origConn := peerUcredSyscallConn
	origControl := peerUcredRawControl
	origGetsockopt := peerUcredGetsockopt
	t.Cleanup(func() {
		peerUcredSyscallConn = origConn
		peerUcredRawControl = origControl
		peerUcredGetsockopt = origGetsockopt
	})

	peerUcredSyscallConn = func(*net.UnixConn) (syscall.RawConn, error) {
		return nil, errors.New("syscallconn")
	}
	if _, err := realPeerUID(&net.UnixConn{}); err == nil {
		t.Fatal("expected UID SyscallConn error")
	}
	if _, err := realPeerPID(&net.UnixConn{}); err == nil {
		t.Fatal("expected PID SyscallConn error")
	}

	peerUcredSyscallConn = func(*net.UnixConn) (syscall.RawConn, error) { return nil, nil }
	peerUcredRawControl = func(syscall.RawConn, func(uintptr)) error { return errors.New("control") }
	if _, err := realPeerUID(&net.UnixConn{}); err == nil {
		t.Fatal("expected UID control error")
	}
	if _, err := realPeerPID(&net.UnixConn{}); err == nil {
		t.Fatal("expected PID control error")
	}

	peerUcredRawControl = func(_ syscall.RawConn, fn func(uintptr)) error {
		fn(0)
		return nil
	}
	peerUcredGetsockopt = func(int, int, int) (*syscall.Ucred, error) {
		return nil, syscall.EINVAL
	}
	if _, err := realPeerUID(&net.UnixConn{}); err == nil {
		t.Fatal("expected UID getsockopt error")
	}
	if _, err := realPeerPID(&net.UnixConn{}); err == nil {
		t.Fatal("expected PID getsockopt error")
	}

	peerUcredGetsockopt = func(int, int, int) (*syscall.Ucred, error) {
		return &syscall.Ucred{Uid: 123, Pid: 456}, nil
	}
	if got, err := realPeerUID(&net.UnixConn{}); err != nil || got != 123 {
		t.Fatalf("realPeerUID success = %d, %v", got, err)
	}
	if got, err := realPeerPID(&net.UnixConn{}); err != nil || got != 456 {
		t.Fatalf("realPeerPID success = %d, %v", got, err)
	}
}

func TestLinuxProcessIdentityBranches(t *testing.T) {
	if got, err := realProcessIdentity(0); err != nil || got != "" {
		t.Fatalf("realProcessIdentity(0) = %q, %v", got, err)
	}

	origReadFile := processIdentityReadFile
	t.Cleanup(func() { processIdentityReadFile = origReadFile })

	processIdentityReadFile = func(string) ([]byte, error) {
		return nil, errors.New("gone")
	}
	if got, err := realProcessIdentity(123); err != nil || got != "" {
		t.Fatalf("read error identity = %q, %v", got, err)
	}

	processIdentityReadFile = func(string) ([]byte, error) {
		return []byte("123 no-close-paren"), nil
	}
	if got, err := realProcessIdentity(123); err != nil || got != "" {
		t.Fatalf("malformed identity = %q, %v", got, err)
	}

	processIdentityReadFile = func(string) ([]byte, error) {
		return []byte("123 (hasp test) S 1 2 3"), nil
	}
	if got, err := realProcessIdentity(123); err != nil || got != "" {
		t.Fatalf("short stat identity = %q, %v", got, err)
	}

	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[19] = "424242"
	processIdentityReadFile = func(string) ([]byte, error) {
		return []byte("123 (hasp test (worker)) " + strings.Join(fields, " ")), nil
	}
	if got, err := realProcessIdentity(123); err != nil || got != "424242" {
		t.Fatalf("valid identity = %q, %v", got, err)
	}
}
