package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
)

type pingErrorService struct{}

func (pingErrorService) Ping(PingRequest, *PingResponse) error { return errors.New("ping failed") }

type badNameService struct{}

func (badNameService) Ping(_ PingRequest, reply *PingResponse) error {
	*reply = PingResponse{Name: "other"}
	return nil
}

func (badNameService) Status(_ StatusRequest, reply *StatusResponse) error {
	*reply = StatusResponse{SocketPath: "/tmp/other.sock", PID: os.Getpid()}
	return nil
}

type statusErrorService struct{}

func (statusErrorService) Ping(_ PingRequest, reply *PingResponse) error {
	*reply = PingResponse{Name: "hasp"}
	return nil
}

func (statusErrorService) Status(StatusRequest, *StatusResponse) error {
	return errors.New("status failed")
}

type acceptErrorListener struct {
	err error
}

func (l *acceptErrorListener) Accept() (net.Conn, error) { return nil, l.err }
func (l *acceptErrorListener) Close() error              { return nil }
func (l *acceptErrorListener) Addr() net.Addr            { return testAddr("unix") }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }

func runtimeSocketPath(prefix string) string {
	return filepath.Join("/tmp", fmt.Sprintf("hasp-%s-%d.sock", prefix, time.Now().UnixNano()))
}

func serveRuntimeRPC(t *testing.T, service any) (string, func()) {
	t.Helper()

	socketPath := runtimeSocketPath("rpc")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	server := rpc.NewServer()
	if err := server.RegisterName("HASP", service); err != nil {
		t.Fatalf("register rpc service: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()

	cleanup := func() {
		_ = listener.Close()
		<-done
		_ = os.Remove(socketPath)
	}
	return socketPath, cleanup
}

func TestNewManagerResolveError(t *testing.T) {
	lockRuntimeSeams(t)
	origResolve := resolveRuntimePaths
	defer func() { resolveRuntimePaths = origResolve }()

	resolveRuntimePaths = func() (paths.Paths, error) {
		return paths.Paths{}, errors.New("resolve failed")
	}
	if _, err := NewManager(); err == nil {
		t.Fatal("expected resolve error")
	}
}

func TestVerifyDaemonRejectsPingAndStatusFailures(t *testing.T) {
	t.Run("ping error", func(t *testing.T) {
		socketPath, cleanup := serveRuntimeRPC(t, pingErrorService{})
		defer cleanup()

		client, err := Dial(context.Background(), socketPath)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer client.Close()
		if verifyDaemon(context.Background(), client, socketPath) {
			t.Fatal("expected verifyDaemon to reject ping error")
		}
	})

	t.Run("ping name mismatch", func(t *testing.T) {
		socketPath, cleanup := serveRuntimeRPC(t, badNameService{})
		defer cleanup()

		client, err := Dial(context.Background(), socketPath)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer client.Close()
		if verifyDaemon(context.Background(), client, socketPath) {
			t.Fatal("expected verifyDaemon to reject unexpected daemon name")
		}
	})

	t.Run("status error", func(t *testing.T) {
		socketPath, cleanup := serveRuntimeRPC(t, statusErrorService{})
		defer cleanup()

		client, err := Dial(context.Background(), socketPath)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer client.Close()
		if verifyDaemon(context.Background(), client, socketPath) {
			t.Fatal("expected verifyDaemon to reject status error")
		}
	})
}

func TestEnsureDaemonUsesBackgroundWhenContextIsNil(t *testing.T) {
	lockRuntimeSeams(t)
	origSpawn := spawnDaemonProcess
	origMkdir := runtimeMkdirAll
	origRemove := runtimeRemove
	defer func() {
		spawnDaemonProcess = origSpawn
		runtimeMkdirAll = origMkdir
		runtimeRemove = origRemove
	}()

	runtimeMkdirAll = func(string, os.FileMode) error { return nil }
	runtimeRemove = func(string) error { return nil }
	spawnDaemonProcess = func(ctx context.Context) error {
		if ctx == nil {
			t.Fatal("expected background context")
		}
		return errors.New("spawn blocked")
	}

	manager := &Manager{paths: paths.Paths{
		RuntimeDir: t.TempDir(),
		SocketPath: filepath.Join(t.TempDir(), "daemon.sock"),
	}}
	if err := manager.EnsureDaemon(context.Background()); err == nil || !strings.Contains(err.Error(), "spawn blocked") {
		t.Fatalf("expected spawn failure, got %v", err)
	}
}

func TestEnsureDaemonTimesOutWhenDaemonNeverAppears(t *testing.T) {
	lockRuntimeSeams(t)
	origSpawn := spawnDaemonProcess
	origMkdir := runtimeMkdirAll
	origRemove := runtimeRemove
	defer func() {
		spawnDaemonProcess = origSpawn
		runtimeMkdirAll = origMkdir
		runtimeRemove = origRemove
	}()

	runtimeMkdirAll = func(string, os.FileMode) error { return nil }
	runtimeRemove = func(string) error { return nil }
	spawnDaemonProcess = func(context.Context) error { return nil }

	manager := &Manager{paths: paths.Paths{
		RuntimeDir: t.TempDir(),
		SocketPath: filepath.Join(t.TempDir(), "missing.sock"),
	}}
	start := time.Now()
	err := manager.EnsureDaemon(context.Background())
	if err == nil || !strings.Contains(err.Error(), "timed out waiting for hasp daemon") {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if time.Since(start) < 5*time.Second {
		t.Fatal("expected real timeout wait")
	}
}

func TestManagerStartDaemonUsesBackgroundWhenNil(t *testing.T) {
	lockRuntimeSeams(t)
	origSpawn := spawnDaemonProcess
	defer func() { spawnDaemonProcess = origSpawn }()

	spawnDaemonProcess = func(ctx context.Context) error {
		if ctx == nil {
			t.Fatal("expected background context")
		}
		return nil
	}

	if err := (&Manager{}).StartDaemon(context.Background()); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
}

func TestRunDaemonUsesBackgroundWhenNilAndMkdirFailure(t *testing.T) {
	lockRuntimeSeams(t)
	origMkdir := runtimeMkdirAll
	defer func() { runtimeMkdirAll = origMkdir }()

	runtimeMkdirAll = func(string, os.FileMode) error { return errors.New("mkdir failed") }
	manager := &Manager{paths: paths.Paths{
		RuntimeDir:  t.TempDir(),
		SocketPath:  filepath.Join(t.TempDir(), "daemon.sock"),
		PidFilePath: filepath.Join(t.TempDir(), "daemon.pid"),
	}}
	if err := manager.RunDaemon(context.Background()); err == nil || !strings.Contains(err.Error(), "create runtime dir") {
		t.Fatalf("expected mkdir error, got %v", err)
	}
}

func TestRunDaemonReturnsRemoveStaleSocketError(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "daemon.sock")
	if err := os.WriteFile(socketPath, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write fake socket: %v", err)
	}
	manager := &Manager{paths: paths.Paths{
		RuntimeDir:  dir,
		SocketPath:  socketPath,
		PidFilePath: filepath.Join(dir, "daemon.pid"),
	}}
	if err := manager.RunDaemon(context.Background()); err == nil || !strings.Contains(err.Error(), "refusing to remove non-socket") {
		t.Fatalf("expected stale socket error, got %v", err)
	}
}

func TestRunDaemonReturnsRegisterError(t *testing.T) {
	lockRuntimeSeams(t)
	origRegister := registerServerName
	defer func() { registerServerName = origRegister }()

	registerServerName = func(*rpc.Server, string, any) error { return errors.New("register failed") }
	manager := &Manager{paths: paths.Paths{
		RuntimeDir:  t.TempDir(),
		SocketPath:  runtimeSocketPath("register"),
		PidFilePath: filepath.Join(t.TempDir(), "daemon.pid"),
	}}
	if err := manager.RunDaemon(context.Background()); err == nil || !strings.Contains(err.Error(), "register failed") {
		t.Fatalf("expected register error, got %v", err)
	}
}

func TestRunDaemonReturnsServeError(t *testing.T) {
	lockRuntimeSeams(t)
	origListen := listenUnix
	origChmod := chmodFile
	origWrite := writeFile
	origRemove := runtimeRemove
	origMkdir := runtimeMkdirAll
	defer func() {
		listenUnix = origListen
		chmodFile = origChmod
		writeFile = origWrite
		runtimeRemove = origRemove
		runtimeMkdirAll = origMkdir
	}()

	listenUnix = func(string, string) (net.Listener, error) {
		return &acceptErrorListener{err: errors.New("accept failed")}, nil
	}
	chmodFile = func(string, os.FileMode) error { return nil }
	writeFile = func(string, []byte, os.FileMode) error { return nil }
	runtimeRemove = func(string) error { return nil }
	runtimeMkdirAll = func(string, os.FileMode) error { return nil }

	manager := &Manager{paths: paths.Paths{
		RuntimeDir:  t.TempDir(),
		SocketPath:  filepath.Join(t.TempDir(), "daemon.sock"),
		PidFilePath: filepath.Join(t.TempDir(), "daemon.pid"),
	}}
	if err := manager.RunDaemon(context.Background()); err == nil || !strings.Contains(err.Error(), "accept failed") {
		t.Fatalf("expected serve error, got %v", err)
	}
}

func TestBrokerRPCOpenSessionPropagatesSessionStoreErrors(t *testing.T) {
	lockRuntimeSeams(t)
	origUser := currentUserFn
	defer func() { currentUserFn = origUser }()

	currentUserFn = func() (*user.User, error) {
		return nil, errors.New("user lookup failed")
	}

	broker := &brokerRPC{
		paths:     paths.Paths{SocketPath: filepath.Join(t.TempDir(), "daemon.sock")},
		startedAt: time.Now().UTC(),
		sessions:  NewSessionStore(),
	}

	var reply OpenSessionResponse
	err := broker.OpenSession(OpenSessionRequest{
		HostLabel:   "agent",
		ProjectRoot: t.TempDir(),
		TTLSeconds:  60,
	}, &reply)
	if err == nil || !strings.Contains(err.Error(), "user lookup failed") {
		t.Fatalf("expected session store error, got %v", err)
	}
}

func TestBrokerRPCOpenSessionAndRevokeWriteAuditEntries(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(paths.EnvHome, dir)
	t.Setenv(paths.EnvSocket, filepath.Join(dir, "daemon.sock"))

	log, err := audit.New()
	if err != nil {
		t.Fatalf("create audit log: %v", err)
	}
	auditKey := []byte("0123456789abcdef0123456789abcdef")
	if _, err := log.WithKey(auditKey).Append(audit.EventInit, "user", map[string]any{"version": "test"}); err != nil {
		t.Fatalf("seed keyed audit log: %v", err)
	}
	log.WithKey(nil)
	broker := &brokerRPC{
		paths:     paths.Paths{SocketPath: filepath.Join(dir, "daemon.sock")},
		startedAt: time.Now().UTC(),
		sessions:  NewSessionStore(),
		audit:     log,
	}

	var openReply OpenSessionResponse
	if err := broker.OpenSession(OpenSessionRequest{
		HostLabel:    "agent",
		ProjectRoot:  dir,
		TTLSeconds:   60,
		AuditHMACKey: auditKey,
	}, &openReply); err != nil {
		t.Fatalf("open session: %v", err)
	}

	var revokeReply RevokeSessionResponse
	if err := broker.RevokeSession(RevokeSessionRequest{SessionToken: openReply.SessionToken}, &revokeReply); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if !revokeReply.Revoked {
		t.Fatal("expected revoke to succeed")
	}
	events, err := log.Events()
	if err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected init, open, and revoke audit events, got %d", len(events))
	}
	for _, event := range events {
		if event.Scheme != audit.SchemeHMACSHA256V1 {
			t.Fatalf("event %d scheme = %q, want %q", event.Sequence, event.Scheme, audit.SchemeHMACSHA256V1)
		}
	}
	if err := log.WithKey(auditKey).Verify(); err != nil {
		t.Fatalf("verify keyed daemon audit chain: %v", err)
	}

	var rejectedReply OpenSessionResponse
	wrongKey := []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	if err := broker.OpenSession(OpenSessionRequest{
		HostLabel:    "agent",
		ProjectRoot:  dir,
		TTLSeconds:   60,
		AuditHMACKey: wrongKey,
	}, &rejectedReply); err == nil {
		t.Fatal("expected untrusted audit key to be rejected")
	}
	if rejectedReply.SessionToken != "" {
		t.Fatalf("rejected open returned session token %q", rejectedReply.SessionToken)
	}
	if err := log.WithKey(auditKey).Verify(); err != nil {
		t.Fatalf("wrong caller key must not corrupt keyed daemon audit chain: %v", err)
	}
	sessions := broker.sessions.Snapshot()
	if len(sessions) != 0 {
		t.Fatalf("rejected open left active sessions: %+v", sessions)
	}
}

func TestRemoveStaleSocketStatAndRemoveErrors(t *testing.T) {
	t.Run("stat failure", func(t *testing.T) {
		if err := removeStaleSocket("bad\x00path"); err == nil || !strings.Contains(err.Error(), "stat socket path") {
			t.Fatalf("expected stat error, got %v", err)
		}
	})

	t.Run("remove failure", func(t *testing.T) {
		dir := filepath.Join("/tmp", fmt.Sprintf("hasp-remove-fail-%d", time.Now().UnixNano()))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("mkdir socket dir: %v", err)
		}
		defer os.RemoveAll(dir)
		socketPath := filepath.Join(dir, "daemon.sock")
		listener, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatalf("listen socket: %v", err)
		}
		defer listener.Close()
		if _, err := os.Stat(socketPath); err != nil {
			t.Fatalf("stat socket file: %v", err)
		}

		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatalf("chmod dir: %v", err)
		}
		defer func() { _ = os.Chmod(dir, 0o700) }()

		err = removeStaleSocket(socketPath)
		if err == nil || !strings.Contains(err.Error(), "remove stale socket") {
			t.Fatalf("expected remove error, got %v", err)
		}
	})

	t.Run("remove success", func(t *testing.T) {
		dir := filepath.Join("/tmp", fmt.Sprintf("hasp-remove-success-%d", time.Now().UnixNano()))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("mkdir socket dir: %v", err)
		}
		defer os.RemoveAll(dir)
		socketPath := filepath.Join(dir, "daemon.sock")
		listener, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatalf("listen socket: %v", err)
		}
		defer listener.Close()
		if err := removeStaleSocket(socketPath); err != nil {
			t.Fatalf("remove stale socket: %v", err)
		}
	})
}
