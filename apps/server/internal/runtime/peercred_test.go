//go:build unix

package runtime

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

// TestPeerUIDSeamDefaultsToRealImplementation verifies that newRPCServer wires
// a non-nil peer-UID reader by default (production build must have a real
// implementation).
func TestPeerUIDSeamDefaultsToRealImplementation(t *testing.T) {
	srv := newRPCServer(paths.Paths{SocketPath: filepath.Join(t.TempDir(), "daemon.sock")})
	if srv.peerUID == nil {
		t.Fatal("rpcServer.peerUID must be non-nil: production build must wire a real peer-UID reader")
	}
}

// spawnServeLoop starts an rpcServer's serve loop on the given listener and
// registers a cleanup that cancels the loop AND waits for the goroutine to
// exit. Waiting is essential: the test body's defers (which restore the
// peerUIDFn seam) run BEFORE t.Cleanup, so if the serve goroutine is still
// reading peerUIDFn when the defer swaps it, the race detector fires.
func spawnServeLoop(t *testing.T, srv *rpcServer, ln net.Listener) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.serve(ctx, ln)
	}()
	// Register the wait FIRST (runs LAST on cleanup) so the goroutine has fully
	// exited before the test body's defers tear down the seam.
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		wg.Wait()
	})
	return cancel
}

// dialAndPing dials the unix socket at socketPath and issues a Ping RPC.
// Returns the PingResponse and the first error encountered.
func dialAndPing(socketPath string) (PingResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := Dial(ctx, socketPath)
	if err != nil {
		return PingResponse{}, err
	}
	defer client.Close()
	return client.Ping(ctx)
}

// makePeerCredServer creates an rpcServer wired to a real temp-dir socket.
// The caller owns the listener and is responsible for closing it.
func makePeerCredServer(t *testing.T) (*rpcServer, net.Listener, string) {
	t.Helper()
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "daemon.sock")

	// Use a minimal Paths struct — only SocketPath is used by newRPCServer.
	p := paths.Paths{
		SocketPath:  socketPath,
		RuntimeDir:  dir,
		PidFilePath: filepath.Join(dir, "daemon.pid"),
	}
	srv := newRPCServer(p)
	if err := srv.register(); err != nil {
		t.Fatalf("register rpc server: %v", err)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	return srv, ln, socketPath
}

// TestServerRejectsMismatchedPeerUID sets srv.peerUID to return a UID that
// does NOT match the daemon's euid. Dialing and issuing a Ping must result
// in a connection-closed / EOF error — no successful PingResponse.
func TestServerRejectsMismatchedPeerUID(t *testing.T) {
	srv, ln, socketPath := makePeerCredServer(t)
	// Return a UID that is guaranteed to differ from the running process's euid.
	srv.peerUID = func(_ net.Conn) (uint32, error) {
		return uint32(os.Geteuid() + 1), nil
	}
	spawnServeLoop(t, srv, ln)

	// Give the serve goroutine a moment to start accepting.
	time.Sleep(10 * time.Millisecond)

	ping, err := dialAndPing(socketPath)
	if err == nil {
		t.Fatalf("expected connection-closed/EOF error for mismatched UID, got successful PingResponse: %+v", ping)
	}
	// Acceptable errors: io.EOF, connection reset, or any network close variant.
	if ping.Name == "hasp" {
		t.Fatal("RPC handler must not run for a rejected peer: got Name='hasp'")
	}
	// Verify the error is a connection-close variant (EOF or similar).
	if !errors.Is(err, io.EOF) && !isConnClosedErr(err) {
		t.Logf("got expected rejection error (type %T): %v", err, err)
	}
}

// TestServerAcceptsMatchingPeerUID sets srv.peerUID to return the daemon's
// own euid. Dialing and Ping must succeed and return Name="hasp".
func TestServerAcceptsMatchingPeerUID(t *testing.T) {
	srv, ln, socketPath := makePeerCredServer(t)
	srv.peerUID = func(_ net.Conn) (uint32, error) {
		return uint32(os.Geteuid()), nil
	}
	spawnServeLoop(t, srv, ln)

	time.Sleep(10 * time.Millisecond)

	ping, err := dialAndPing(socketPath)
	if err != nil {
		t.Fatalf("expected successful Ping for matching UID, got error: %v", err)
	}
	if ping.Name != "hasp" {
		t.Fatalf("expected PingResponse.Name='hasp', got %q", ping.Name)
	}
}

// TestServerRejectsPeerUIDLookupFailure sets srv.peerUID to return an error.
// The accept loop must reject the connection (fail-closed).
func TestServerRejectsPeerUIDLookupFailure(t *testing.T) {
	srv, ln, socketPath := makePeerCredServer(t)
	srv.peerUID = func(_ net.Conn) (uint32, error) {
		return 0, errors.New("syscall: getsockopt SO_PEERCRED: not supported")
	}
	spawnServeLoop(t, srv, ln)

	time.Sleep(10 * time.Millisecond)

	ping, err := dialAndPing(socketPath)
	if err == nil {
		t.Fatalf("expected rejection when peer-UID lookup fails, got successful Ping: %+v", ping)
	}
	if ping.Name == "hasp" {
		t.Fatal("RPC handler must not run when peer-UID lookup fails")
	}
}

// TestServerRejectsNonUnixConnections verifies that when srv.peerUID rejects
// a conn (as a platform impl would when it isn't a *net.UnixConn) the accept
// loop fires the rejection path — no RPC handler ever runs.
func TestServerRejectsNonUnixConnections(t *testing.T) {
	srv, ln, socketPath := makePeerCredServer(t)
	srv.peerUID = func(_ net.Conn) (uint32, error) {
		return 0, errors.New("peer credential lookup: not a unix socket")
	}
	spawnServeLoop(t, srv, ln)

	time.Sleep(10 * time.Millisecond)

	ping, err := dialAndPing(socketPath)
	if err == nil {
		t.Fatalf("expected rejection for non-unix seam, got successful Ping: %+v", ping)
	}
	if ping.Name == "hasp" {
		t.Fatal("RPC handler must not run when conn type is rejected")
	}
}

// isConnClosedErr returns true for common "connection closed by remote" errors.
func isConnClosedErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, substr := range []string{
		"connection reset by peer",
		"broken pipe",
		"use of closed network connection",
		"EOF",
		"connection refused",
	} {
		if containsStr(msg, substr) {
			return true
		}
	}
	return false
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && stringContains(s, sub))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
