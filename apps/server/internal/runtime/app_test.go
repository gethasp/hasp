package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestMain(m *testing.M) {
	if os.Getenv("HASP_TEST_HELPER_DAEMON") == "1" && len(os.Args) >= 3 && os.Args[1] == "daemon" && os.Args[2] == "serve" {
		manager, err := NewManager()
		if err != nil {
			os.Exit(2)
		}
		ctx, cancel := testHelperDaemonContext()
		err = manager.RunDaemon(ctx)
		cancel()
		if err != nil {
			os.Exit(3)
		}
		return
	}
	// Always point HASP_HOME at a temp dir so runtime tests never touch the
	// real ~/.hasp directory.  Individual tests may call t.Setenv("HASP_HOME",
	// t.TempDir()) to get their own isolated directory; t.Setenv restores the
	// process-level value set here on test cleanup.
	os.Setenv("HASP_TEST_HELPER_DAEMON", "1")
	dir, err := os.MkdirTemp("", "hasp-test-runtime-*")
	if err == nil {
		os.Setenv("HASP_HOME", dir)
	}
	os.Setenv("HASP_TEST", "1")
	code := m.Run()
	if dir != "" {
		os.RemoveAll(dir)
	}
	os.Exit(code)
}

func testHelperDaemonContext() (context.Context, context.CancelFunc) {
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	parentPID, err := strconv.Atoi(os.Getenv("HASP_TEST_HELPER_PARENT_PID"))
	if err != nil || parentPID <= 0 {
		return ctx, stopSignals
	}
	parentCtx, cancelParent := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		defer cancelParent()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := syscall.Kill(parentPID, 0); errors.Is(err, syscall.ESRCH) {
					return
				}
			}
		}
	}()
	return parentCtx, func() {
		cancelParent()
		stopSignals()
	}
}

func TestHelperDaemonContextCancelsWhenParentIsGone(t *testing.T) {
	t.Setenv("HASP_TEST_HELPER_PARENT_PID", "999999")
	ctx, cancel := testHelperDaemonContext()
	defer cancel()

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("helper daemon context did not cancel for missing parent")
	}
}

func TestSessionStoreOpenAndRevoke(t *testing.T) {
	store := NewSessionStore()
	session, err := store.Open("test-host", "/tmp/project/../project", time.Minute, false, "")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if session.Token == "" || session.ID == "" {
		t.Fatalf("expected token and id")
	}
	if session.ProjectRoot != "/tmp/project" {
		t.Fatalf("project root = %q", session.ProjectRoot)
	}
	if session.LocalUser == "" {
		t.Fatalf("expected local user")
	}
	if count := store.ActiveCount(); count != 1 {
		t.Fatalf("active count = %d, want 1", count)
	}
	if !store.Revoke(session.Token) {
		t.Fatalf("expected revoke to succeed")
	}
	if count := store.ActiveCount(); count != 0 {
		t.Fatalf("active count = %d, want 0", count)
	}
}

func TestSessionStoreResolveExtendsActivity(t *testing.T) {
	store := NewSessionStore()
	session, err := store.Open("test-host", "/tmp/project", time.Minute, false, "")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}

	time.Sleep(2 * time.Millisecond)

	resolved, ok := store.Resolve(session.Token)
	if !ok {
		t.Fatal("expected resolve to succeed")
	}
	if !resolved.LastSeenAt.After(session.LastSeenAt) {
		t.Fatal("expected last_seen_at to move forward")
	}
}

func TestRPCServerOpenSessionAndStatus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolved, err := paths.Resolve()
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	server := newRPCServer(resolved)
	if err := server.register(); err != nil {
		t.Fatalf("register rpc server: %v", err)
	}

	session, err := server.sessions.Open("agent", "/tmp/project", time.Minute, true, "agent")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if session.HostLabel != "agent" {
		t.Fatalf("host label = %q", session.HostLabel)
	}
	if server.sessions.ActiveCount() != 1 {
		t.Fatalf("active count = %d, want 1", server.sessions.ActiveCount())
	}
	server.sessions.processIdentity = func(int) (string, error) { return "", nil }
	if !server.sessions.RegisterProcess(session.Token, 12345) {
		t.Fatal("register process for degraded identity status")
	}
	if session.ExpiresAt.Sub(time.Now().UTC()) > DefaultSessionTTL+time.Second {
		t.Fatalf("session ttl exceeded limit")
	}
	var status StatusResponse
	if err := (&brokerRPC{
		paths:     resolved,
		startedAt: time.Now().UTC(),
		sessions:  server.sessions,
	}).Status(StatusRequest{}, &status); err != nil {
		t.Fatalf("status: %v", err)
	}
	if len(status.Sessions) != 1 {
		t.Fatalf("expected one active session in status")
	}
	if status.Sessions[0].ID != session.ID {
		t.Fatalf("status session id = %q, want %q", status.Sessions[0].ID, session.ID)
	}
	if !status.Sessions[0].AgentSafe || status.Sessions[0].ConsumerName != "agent" {
		t.Fatalf("expected agent-safe session metadata, got %+v", status.Sessions[0])
	}
	if !status.ProcessIdentityDegraded || status.ProcessIdentityDegradedReason == "" {
		t.Fatalf("expected process identity degradation in status, got %+v", status)
	}
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	default:
	}
}

func TestOpenSessionClampsTTL(t *testing.T) {
	resolved, err := paths.Resolve()
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	broker := &brokerRPC{
		paths:     resolved,
		startedAt: time.Now().UTC(),
		sessions:  NewSessionStore(),
	}
	var reply OpenSessionResponse
	if err := broker.OpenSession(OpenSessionRequest{
		HostLabel:   "agent",
		ProjectRoot: "/tmp/project",
		TTLSeconds:  int((DefaultSessionTTL + time.Hour).Seconds()),
	}, &reply); err != nil {
		t.Fatalf("open session: %v", err)
	}
	if reply.ExpiresAt.Sub(time.Now().UTC()) > DefaultSessionTTL+time.Second {
		t.Fatalf("clamped ttl exceeded limit")
	}
}

func TestManagerEnsureDaemonStartsServer(t *testing.T) {
	lockRuntimeSeams(t)
	baseDir := t.TempDir()
	t.Setenv("HASP_HOME", baseDir)
	socketPath := filepath.Join("/tmp", fmt.Sprintf("hasp-%d.sock", time.Now().UnixNano()))
	t.Setenv("HASP_SOCKET", socketPath)
	t.Cleanup(func() {
		_ = os.Remove(socketPath)
	})

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	defer func() {
		cancel()
		select {
		case err := <-runErr:
			if err != nil {
				t.Fatalf("daemon shutdown: %v", err)
			}
		case <-time.After(10 * time.Second):
			// CI coverage runs leave daemon shutdown contended; widen this
			// safety cap so a slow scheduler tick doesn't fail a clean test.
			t.Fatal("timed out waiting for daemon shutdown")
		}
	}()

	original := spawnDaemonProcess
	t.Cleanup(func() { spawnDaemonProcess = original })
	spawnDaemonProcess = func(context.Context) error {
		go func() {
			daemonCtx, daemonCancel := context.WithCancel(context.Background())
			defer daemonCancel()
			go func() {
				<-ctx.Done()
				daemonCancel()
			}()
			runErr <- manager.RunDaemon(daemonCtx)
		}()
		if err := waitForSocket(manager.SocketPath(), 2*time.Second); err != nil {
			select {
			case daemonErr := <-runErr:
				if daemonErr != nil {
					return daemonErr
				}
			default:
			}
			return err
		}
		return nil
	}

	if err := manager.EnsureDaemon(ctx); err != nil {
		t.Fatalf("ensure daemon: %v", err)
	}

	if _, err := os.Stat(manager.paths.PidFilePath); err != nil {
		t.Fatalf("expected pid file: %v", err)
	}
	client, err := Dial(ctx, manager.SocketPath())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer client.Close()
	if _, err := client.Ping(ctx); err != nil {
		t.Fatalf("ping daemon: %v", err)
	}

	sessionReply, err := client.OpenSession(ctx, OpenSessionRequest{
		HostLabel:   "claude-code",
		ProjectRoot: filepath.Join(baseDir, "project", "..", "project"),
		TTLSeconds:  60,
	})
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if sessionReply.LocalUser == "" {
		t.Fatal("expected local user")
	}
	if sessionReply.ProjectRoot != filepath.Join(baseDir, "project") {
		t.Fatalf("project root = %q", sessionReply.ProjectRoot)
	}

	resolvedReply, err := client.ResolveSession(ctx, sessionReply.SessionToken)
	if err != nil {
		t.Fatalf("resolve session: %v", err)
	}
	if resolvedReply.Session.ID != sessionReply.SessionID {
		t.Fatalf("resolved session id = %q, want %q", resolvedReply.Session.ID, sessionReply.SessionID)
	}
	if resolvedReply.Session.ProjectRoot != filepath.Join(baseDir, "project") {
		t.Fatalf("resolved project root = %q", resolvedReply.Session.ProjectRoot)
	}
}

func TestOpenSessionRequiresHostLabel(t *testing.T) {
	resolved, err := paths.Resolve()
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	server := newRPCServer(resolved)
	if err := server.register(); err != nil {
		t.Fatalf("register rpc server: %v", err)
	}

	var reply OpenSessionResponse
	err = (&brokerRPC{
		paths:     resolved,
		startedAt: time.Now().UTC(),
		sessions:  NewSessionStore(),
	}).OpenSession(OpenSessionRequest{TTLSeconds: 60}, &reply)
	if err == nil {
		t.Fatal("expected host label error")
	}
}

func TestRemoveStaleSocketRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	if err := removeStaleSocket(path); err == nil {
		t.Fatal("expected refusal for non-socket file")
	}
}

func TestSessionStorePrunesExpiredSessions(t *testing.T) {
	store := NewSessionStore()
	session, err := store.Open("test-host", "/tmp/project", time.Millisecond, false, "")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	store.PruneExpired()
	if store.Revoke(session.Token) {
		t.Fatal("expected expired session to be pruned")
	}
}

func TestSessionStoreResolveExpiredAndMissing(t *testing.T) {
	store := NewSessionStore()
	if _, ok := store.Resolve("missing"); ok {
		t.Fatal("expected missing session resolve to fail")
	}
	session, err := store.Open("test-host", "/tmp/project", time.Millisecond, false, "")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, ok := store.Resolve(session.Token); ok {
		t.Fatal("expected expired session resolve to fail")
	}
}

func TestBrokerRevokeSessionAndManagerStartStop(t *testing.T) {
	baseDir := t.TempDir()
	socketPath := filepath.Join("/tmp", fmt.Sprintf("hasp-start-stop-%d.sock", time.Now().UnixNano()))
	t.Setenv("HASP_HOME", baseDir)
	t.Setenv("HASP_SOCKET", socketPath)
	t.Setenv("HASP_TEST_HELPER_DAEMON", "1")
	t.Cleanup(func() {
		_ = os.Remove(socketPath)
	})

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := manager.StartDaemon(context.Background()); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	if err := waitForSocket(manager.SocketPath(), 2*time.Second); err != nil {
		t.Fatalf("wait for socket: %v", err)
	}
	client, err := Dial(context.Background(), manager.SocketPath())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer client.Close()
	sessionReply, err := client.OpenSession(context.Background(), OpenSessionRequest{
		HostLabel:   "runtime-test",
		ProjectRoot: filepath.Join(baseDir, "project"),
		TTLSeconds:  60,
	})
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if err := client.RevokeSession(context.Background(), sessionReply.SessionToken); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if _, err := client.ResolveSession(context.Background(), sessionReply.SessionToken); err == nil {
		t.Fatal("expected revoked session resolution to fail")
	}
	if err := manager.StopDaemon(); err != nil {
		t.Fatalf("stop daemon: %v", err)
	}
}

func TestBrokerRPCRevokeSessionMethod(t *testing.T) {
	resolved, err := paths.Resolve()
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	broker := &brokerRPC{
		paths:     resolved,
		startedAt: time.Now().UTC(),
		sessions:  NewSessionStore(),
	}
	session, err := broker.sessions.Open("agent", "/tmp/project", time.Minute, true, "agent")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	var reply RevokeSessionResponse
	if err := broker.RevokeSession(RevokeSessionRequest{SessionToken: session.Token}, &reply); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if !reply.Revoked {
		t.Fatal("expected revoke reply")
	}
}

func TestBrokerRPCResolveAndRevokeEdgeCases(t *testing.T) {
	resolved, err := paths.Resolve()
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	broker := &brokerRPC{
		paths:     resolved,
		startedAt: time.Now().UTC(),
		sessions:  NewSessionStore(),
	}
	var resolveReply ResolveSessionResponse
	if err := broker.ResolveSession(ResolveSessionRequest{}, &resolveReply); err == nil {
		t.Fatal("expected missing token resolve error")
	}
	if err := broker.ResolveSession(ResolveSessionRequest{SessionToken: "missing"}, &resolveReply); err == nil {
		t.Fatal("expected missing session resolve error")
	}
	var revokeReply RevokeSessionResponse
	if err := broker.RevokeSession(RevokeSessionRequest{}, &revokeReply); err == nil {
		t.Fatal("expected missing token revoke error")
	}
	if err := broker.RevokeSession(RevokeSessionRequest{SessionToken: "missing"}, &revokeReply); err != nil {
		t.Fatalf("unexpected revoke error for missing token: %v", err)
	}
	if revokeReply.Revoked {
		t.Fatal("expected non-revoked reply for missing token")
	}
}

func TestEnsureDaemonRemovesUntrustedSocket(t *testing.T) {
	baseDir := t.TempDir()
	socketPath := filepath.Join("/tmp", fmt.Sprintf("hasp-untrusted-%d.sock", time.Now().UnixNano()))
	t.Setenv("HASP_HOME", baseDir)
	t.Setenv("HASP_SOCKET", socketPath)
	t.Setenv("HASP_TEST_HELPER_DAEMON", "1")
	if err := os.WriteFile(socketPath, []byte("not-a-socket"), 0o600); err != nil {
		t.Fatalf("write fake socket file: %v", err)
	}
	manager, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := manager.EnsureDaemon(context.Background()); err != nil {
		t.Fatalf("ensure daemon: %v", err)
	}
	if err := waitForSocket(manager.SocketPath(), 2*time.Second); err != nil {
		t.Fatalf("wait for socket: %v", err)
	}
	_ = manager.StopDaemon()
}

func TestEnsureDaemonFailurePaths(t *testing.T) {
	lockRuntimeSeams(t)
	baseDir := t.TempDir()
	socketPath := filepath.Join("/tmp", fmt.Sprintf("hasp-failure-%d.sock", time.Now().UnixNano()))
	t.Setenv("HASP_HOME", baseDir)
	t.Setenv("HASP_SOCKET", socketPath)

	origMkdir := runtimeMkdirAll
	origSpawn := spawnDaemonProcess
	origRemove := runtimeRemove
	defer func() {
		runtimeMkdirAll = origMkdir
		spawnDaemonProcess = origSpawn
		runtimeRemove = origRemove
	}()

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	runtimeMkdirAll = func(string, os.FileMode) error { return fmt.Errorf("mkdir fail") }
	if err := manager.EnsureDaemon(context.Background()); err == nil {
		t.Fatal("expected mkdir failure")
	}

	runtimeMkdirAll = origMkdir
	if err := os.WriteFile(socketPath, []byte("not-a-socket"), 0o600); err != nil {
		t.Fatalf("write fake socket: %v", err)
	}
	runtimeRemove = func(string) error { return fmt.Errorf("remove fail") }
	if err := manager.EnsureDaemon(context.Background()); err == nil {
		t.Fatal("expected remove failure")
	}

	runtimeRemove = origRemove
	spawnDaemonProcess = func(context.Context) error { return fmt.Errorf("spawn fail") }
	if err := manager.EnsureDaemon(context.Background()); err == nil {
		t.Fatal("expected spawn failure")
	}
}

func TestRunDaemonListenFailure(t *testing.T) {
	lockRuntimeSeams(t)
	baseDir := t.TempDir()
	socketPath := filepath.Join("/tmp", fmt.Sprintf("hasp-listen-fail-%d.sock", time.Now().UnixNano()))
	t.Setenv("HASP_HOME", baseDir)
	t.Setenv("HASP_SOCKET", socketPath)
	manager, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	origListen := listenUnix
	defer func() { listenUnix = origListen }()
	listenUnix = func(string, string) (net.Listener, error) { return nil, fmt.Errorf("listen fail") }
	if err := manager.RunDaemon(context.Background()); err == nil {
		t.Fatal("expected listen failure")
	}
}

func TestRemoveStaleSocketMissingAndSocketFile(t *testing.T) {
	path := filepath.Join("/tmp", fmt.Sprintf("hasp-remove-%d.sock", time.Now().UnixNano()))
	if err := removeStaleSocket(path); err != nil {
		t.Fatalf("remove missing socket: %v", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen socket: %v", err)
	}
	_ = listener.Close()
	if err := removeStaleSocket(path); err != nil {
		t.Fatalf("remove stale socket: %v", err)
	}
}

func TestSessionHelpers(t *testing.T) {
	session := Session{ID: "abc", HostLabel: "host", LocalUser: "user", ProjectRoot: "/tmp/project", ExpiresAt: time.Now(), LastSeenAt: time.Now()}
	view := session.View()
	if view.ID != session.ID || view.ProjectRoot != session.ProjectRoot {
		t.Fatalf("unexpected session view: %+v", view)
	}
	random, err := randomHex(8)
	if err != nil {
		t.Fatalf("random hex: %v", err)
	}
	if len(random) != 16 {
		t.Fatalf("unexpected random hex length")
	}
}

func TestCanonicalProjectRootAndCurrentUserFallbacks(t *testing.T) {
	lockRuntimeSeams(t)
	origGit := gitTopLevelFn
	origUser := currentUserFn
	defer func() {
		gitTopLevelFn = origGit
		currentUserFn = origUser
	}()

	gitTopLevelFn = func(string) ([]byte, error) { return nil, fmt.Errorf("git fail") }
	projectRoot := CanonicalProjectRoot("/tmp/project/../project")
	if projectRoot != "/tmp/project" {
		t.Fatalf("canonical root = %q", projectRoot)
	}

	currentUserFn = func() (*user.User, error) { return &user.User{Uid: "1234"}, nil }
	name, err := currentUser()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	if name != "1234" {
		t.Fatalf("current user = %q", name)
	}

	currentUserFn = func() (*user.User, error) { return nil, fmt.Errorf("user fail") }
	if _, err := currentUser(); err == nil {
		t.Fatal("expected current user failure")
	}
}

func TestSessionStoreOpenValidationAndGitRootResolution(t *testing.T) {
	lockRuntimeSeams(t)
	store := NewSessionStore()
	if _, err := store.Open("test-host", "/tmp/project", 0, false, ""); err == nil {
		t.Fatal("expected ttl validation error")
	}

	origGit := gitTopLevelFn
	defer func() { gitTopLevelFn = origGit }()
	gitTopLevelFn = func(string) ([]byte, error) { return []byte("/tmp/git-root\n"), nil }
	if got := CanonicalProjectRoot("/tmp/project/nested"); got != "/tmp/git-root" {
		t.Fatalf("canonical project root = %q", got)
	}
}

func TestStartDaemonFailurePath(t *testing.T) {
	lockRuntimeSeams(t)
	origSpawn := spawnDaemonProcess
	defer func() { spawnDaemonProcess = origSpawn }()
	spawnDaemonProcess = func(context.Context) error { return fmt.Errorf("spawn fail") }
	manager, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := manager.StartDaemon(context.Background()); err == nil {
		t.Fatal("expected start daemon failure")
	}
}

func TestRunDaemonChmodAndPidWriteFailures(t *testing.T) {
	lockRuntimeSeams(t)
	baseDir := t.TempDir()
	socketPath := filepath.Join("/tmp", fmt.Sprintf("hasp-run-fail-%d.sock", time.Now().UnixNano()))
	t.Setenv("HASP_HOME", baseDir)
	t.Setenv("HASP_SOCKET", socketPath)
	manager, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	origChmod := chmodFile
	origWrite := writeFile
	origListen := listenUnix
	defer func() {
		chmodFile = origChmod
		writeFile = origWrite
		listenUnix = origListen
	}()

	chmodFile = func(string, os.FileMode) error { return fmt.Errorf("chmod fail") }
	err = manager.RunDaemon(context.Background())
	if err == nil || !strings.Contains(err.Error(), "chmod socket") {
		t.Fatalf("expected chmod failure, got %v", err)
	}

	chmodFile = origChmod
	writeFile = func(string, []byte, os.FileMode) error { return fmt.Errorf("write fail") }
	err = manager.RunDaemon(context.Background())
	if err == nil || !strings.Contains(err.Error(), "write pid file") {
		t.Fatalf("expected pid write failure, got %v", err)
	}
}

func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return context.DeadlineExceeded
}
