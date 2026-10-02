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

func TestLinuxProcessParentPIDRejectsInvalidPIDWithoutReadingProc(t *testing.T) {
	origReadFile := processIdentityReadFile
	t.Cleanup(func() { processIdentityReadFile = origReadFile })
	processIdentityReadFile = func(path string) ([]byte, error) {
		t.Fatalf("unexpected proc read for invalid PID: %s", path)
		return nil, nil
	}

	for _, pid := range []int{0, -1} {
		if parent, err := realProcessParentPID(pid); err != nil || parent != 0 {
			t.Fatalf("realProcessParentPID(%d) = %d, %v", pid, parent, err)
		}
	}
}

func TestLinuxProcessParentPIDParsesProcStat(t *testing.T) {
	readErr := errors.New("process disappeared")
	cases := []struct {
		name    string
		stat    string
		readErr error
		parent  int
		wantErr string
	}{
		{name: "read failure", readErr: readErr, wantErr: "resolve parent pid"},
		{name: "missing command delimiter", stat: "123 hasp S 42", wantErr: "malformed proc stat"},
		{name: "missing fields", stat: "123 (hasp) ", wantErr: "malformed proc stat"},
		{name: "missing parent", stat: "123 (hasp) S", wantErr: "short proc stat"},
		{name: "invalid parent", stat: "123 (hasp) S unknown", wantErr: "parse parent pid"},
		{name: "overflowing parent", stat: "123 (hasp) S 18446744073709551616", wantErr: "parse parent pid"},
		{name: "nested command parentheses", stat: "123 (hasp test (worker)) S 42 100 200", parent: 42},
		{name: "zero parent", stat: "123 (hasp) S 0 100 200", parent: 0},
	}
	origReadFile := processIdentityReadFile
	t.Cleanup(func() { processIdentityReadFile = origReadFile })

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			processIdentityReadFile = func(path string) ([]byte, error) {
				if path != "/proc/123/stat" {
					t.Fatalf("proc path = %q", path)
				}
				return []byte(tc.stat), tc.readErr
			}
			parent, err := realProcessParentPID(123)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || parent != 0 {
					t.Fatalf("parent lookup = %d, %v; want zero parent and %q", parent, err, tc.wantErr)
				}
				if tc.readErr != nil && !errors.Is(err, tc.readErr) {
					t.Fatalf("parent lookup lost read error: %v", err)
				}
				return
			}
			if err != nil || parent != tc.parent {
				t.Fatalf("parent lookup = %d, %v; want %d", parent, err, tc.parent)
			}
		})
	}
}
