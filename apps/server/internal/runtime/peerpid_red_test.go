//go:build unix

package runtime

// RED tests for hasp-sy8 (remainder) — socket-level peer-PID validation at
// session handshake.
//
// Threat: a same-uid attacker dials the daemon socket and calls
// RegisterProcess(pid=<their target's PID>) to bind a session to a process
// they don't own. Peer-UID gate already blocks cross-user attacks; peer-PID
// gate blocks same-uid impersonation.
//
// Contract pinned here:
//   - rpcServer.peerPID is wired by default alongside peerUID.
//   - Accept loop captures the peer PID per-connection.
//   - RegisterProcess rejects with an error when req.PID does NOT match the
//     socket peer's PID (fail-closed).
//   - RegisterProcess accepts when req.PID == socket peer PID.
//   - RegisterProcess fails closed when peerPID returns 0 or an error
//     (lookup unavailable on this platform → privilege ops blocked).

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestPeerPIDSeamDefaultsToRealImplementation(t *testing.T) {
	srv := newRPCServer(paths.Paths{SocketPath: filepath.Join(t.TempDir(), "daemon.sock")})
	if srv.peerPID == nil {
		t.Fatal("rpcServer.peerPID must be non-nil: production build must wire a real peer-PID reader")
	}
}

func TestRegisterProcessRejectsMismatchedPeerPID(t *testing.T) { //nolint:dupl // separate test per rejection cause keeps failures pinpointed
	srv, ln, socketPath := makePeerCredServer(t)
	srv.peerUID = func(_ net.Conn) (uint32, error) { return uint32(os.Geteuid()), nil }
	// Stamp a peer PID that is NOT the test process's PID so RegisterProcess
	// with req.PID = os.Getpid() must be rejected.
	srv.peerPID = func(_ net.Conn) (uint32, error) { return 999_999, nil }
	spawnServeLoop(t, srv, ln)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := Dial(ctx, socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Open a session first — RegisterProcess needs a valid token to address.
	sess, err := client.OpenSession(ctx, OpenSessionRequest{
		HostLabel:   "test-client",
		ProjectRoot: t.TempDir(),
		TTLSeconds:  300,
	})
	if err != nil {
		t.Fatalf("open session: %v", err)
	}

	// req.PID = os.Getpid() but socket peer PID is stamped to 999_999 — must reject.
	if err := client.RegisterProcess(ctx, sess.SessionToken, os.Getpid()); err == nil {
		t.Fatal("expected RegisterProcess to reject when req.PID != socket peer PID")
	}
}

func TestRegisterProcessAcceptsMatchingPeerPID(t *testing.T) {
	srv, ln, socketPath := makePeerCredServer(t)
	srv.peerUID = func(_ net.Conn) (uint32, error) { return uint32(os.Geteuid()), nil }
	srv.peerPID = func(_ net.Conn) (uint32, error) { return uint32(os.Getpid()), nil }
	spawnServeLoop(t, srv, ln)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := Dial(ctx, socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.OpenSession(ctx, OpenSessionRequest{
		HostLabel:   "test-client",
		ProjectRoot: t.TempDir(),
		TTLSeconds:  300,
	})
	if err != nil {
		t.Fatalf("open session: %v", err)
	}

	if err := client.RegisterProcess(ctx, sess.SessionToken, os.Getpid()); err != nil {
		t.Fatalf("RegisterProcess with matching peer PID: %v", err)
	}
}

func TestRegisterProcessRejectsZeroPeerPID(t *testing.T) { //nolint:dupl // separate test per rejection cause keeps failures pinpointed
	srv, ln, socketPath := makePeerCredServer(t)
	srv.peerUID = func(_ net.Conn) (uint32, error) { return uint32(os.Geteuid()), nil }
	// PID = 0 means "unknown" — fail closed for privileged operations.
	srv.peerPID = func(_ net.Conn) (uint32, error) { return 0, nil }
	spawnServeLoop(t, srv, ln)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := Dial(ctx, socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.OpenSession(ctx, OpenSessionRequest{
		HostLabel:   "test-client",
		ProjectRoot: t.TempDir(),
		TTLSeconds:  300,
	})
	if err != nil {
		t.Fatalf("open session: %v", err)
	}

	if err := client.RegisterProcess(ctx, sess.SessionToken, os.Getpid()); err == nil {
		t.Fatal("expected RegisterProcess to fail closed when peer PID is unknown (0)")
	}
}

func TestRegisterProcessRejectsPeerPIDLookupFailure(t *testing.T) {
	srv, ln, socketPath := makePeerCredServer(t)
	srv.peerUID = func(_ net.Conn) (uint32, error) { return uint32(os.Geteuid()), nil }
	srv.peerPID = func(_ net.Conn) (uint32, error) {
		return 0, errors.New("syscall: getsockopt LOCAL_PEERPID: not supported")
	}
	spawnServeLoop(t, srv, ln)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := Dial(ctx, socketPath)
	if err != nil {
		// Connection may already be closed at accept time if we choose the
		// "reject at accept" policy. Either accept-time or RegisterProcess-time
		// rejection is acceptable — both are fail-closed.
		return
	}
	defer client.Close()

	sess, err := client.OpenSession(ctx, OpenSessionRequest{
		HostLabel:   "test-client",
		ProjectRoot: t.TempDir(),
		TTLSeconds:  300,
	})
	if err != nil {
		// Same as above — early rejection is fine.
		return
	}

	if err := client.RegisterProcess(ctx, sess.SessionToken, os.Getpid()); err == nil {
		t.Fatal("expected RegisterProcess to fail closed when peer-PID lookup errored")
	}
}
