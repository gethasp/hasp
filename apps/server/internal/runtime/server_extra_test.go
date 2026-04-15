package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyDaemonRejectsMismatchedSocket(t *testing.T) {
	baseDir := t.TempDir()
	socketPath := filepath.Join("/tmp", "hasp-verify.sock")
	t.Setenv("HASP_HOME", baseDir)
	t.Setenv("HASP_SOCKET", socketPath)
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- manager.RunDaemon(ctx) }()
	if err := waitForSocket(manager.SocketPath(), 2*time.Second); err != nil {
		t.Fatalf("wait for socket: %v", err)
	}
	defer func() {
		cancel()
		<-errCh
	}()

	client, err := Dial(context.Background(), manager.SocketPath())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer client.Close()
	if verifyDaemon(context.Background(), client, "/tmp/other.sock") {
		t.Fatal("expected verifyDaemon to reject mismatched socket")
	}
}

func TestEnsureDaemonReusesHealthySocket(t *testing.T) {
	baseDir := t.TempDir()
	socketPath := filepath.Join("/tmp", "hasp-healthy.sock")
	t.Setenv("HASP_HOME", baseDir)
	t.Setenv("HASP_SOCKET", socketPath)
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- manager.RunDaemon(ctx) }()
	if err := waitForSocket(manager.SocketPath(), 2*time.Second); err != nil {
		t.Fatalf("wait for socket: %v", err)
	}
	defer func() {
		cancel()
		<-errCh
	}()

	if err := manager.EnsureDaemon(context.Background()); err != nil {
		t.Fatalf("ensure daemon on healthy socket: %v", err)
	}
}
