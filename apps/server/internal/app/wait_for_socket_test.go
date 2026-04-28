package app

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hasp-iwlm: under argon2id-driven full-suite load the daemon-test starter
// races the listener bind. waitForSocket previously checked os.Stat on the
// socket file — true even before the listener accepted. The fix is to dial
// the socket; this regression guard exercises the readiness primitive
// directly.

func shortSocketPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "haspsock-")
	if err != nil {
		t.Fatalf("mkdir socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

func TestWaitForSocketReadyTreatsStaleFileAsNotReady(t *testing.T) {
	socketPath := shortSocketPath(t, fmt.Sprintf("stale-%d.sock", time.Now().UnixNano()))
	f, err := os.Create(socketPath)
	if err != nil {
		t.Fatalf("create stale socket file: %v", err)
	}
	_ = f.Close()

	errCh := make(chan error, 1)
	err = waitForSocketReady(socketPath, errCh, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout when only the file exists with no listener")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected a timeout error, got %v", err)
	}
}

func TestWaitForSocketReadyReturnsOnceListenerAccepts(t *testing.T) {
	socketPath := shortSocketPath(t, fmt.Sprintf("ready-%d.sock", time.Now().UnixNano()))
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	errCh := make(chan error, 1)
	if err := waitForSocketReady(socketPath, errCh, time.Second); err != nil {
		t.Fatalf("waitForSocketReady should succeed against an accepting listener; got %v", err)
	}
}

func TestWaitForSocketReadySurfacesEarlyDaemonExit(t *testing.T) {
	socketPath := shortSocketPath(t, fmt.Sprintf("absent-%d.sock", time.Now().UnixNano()))
	errCh := make(chan error, 1)
	errCh <- nil // simulate daemon exiting cleanly before the socket appears

	err := waitForSocketReady(socketPath, errCh, time.Second)
	if err == nil {
		t.Fatal("expected an error when daemon exits before socket is ready")
	}
	if !strings.Contains(err.Error(), "daemon exited") {
		t.Fatalf("expected 'daemon exited' in error, got %v", err)
	}
}
