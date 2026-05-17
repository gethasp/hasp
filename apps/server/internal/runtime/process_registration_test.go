package runtime

import (
	"context"
	"errors"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
)

type FakeHASP struct{}

func (FakeHASP) RegisterProcess(RegisterProcessRequest, *RegisterProcessResponse) error {
	return nil
}

func TestSessionStoreRegisterAndResolveProcess(t *testing.T) {
	store := NewSessionStore()
	session, err := store.Open("agent", t.TempDir(), time.Minute, true, "claude-code")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if store.RegisterProcess("missing", os.Getpid()) {
		t.Fatal("expected missing session registration to fail")
	}
	if store.RegisterProcess(session.Token, 0) {
		t.Fatal("expected invalid pid registration to fail")
	}
	if !store.RegisterProcess(session.Token, os.Getpid()) {
		t.Fatal("expected process registration to succeed")
	}
	resolved, token, ok := store.ResolveProcess(os.Getpid())
	if !ok {
		t.Fatal("expected resolve process to succeed")
	}
	if token != session.Token || !resolved.AgentSafe || resolved.ConsumerName != "claude-code" {
		t.Fatalf("unexpected resolved session %+v token=%q", resolved, token)
	}
	if !store.Revoke(session.Token) {
		t.Fatal("expected revoke to succeed")
	}
	if store.Revoke("missing") {
		t.Fatal("expected missing revoke to report false")
	}
	if _, _, ok := store.ResolveProcess(os.Getpid()); ok {
		t.Fatal("expected revoke to clear process registration")
	}
}

func TestClientRegisterAndResolveProcess(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv("HASP_HOME", baseDir)
	socketPath := filepath.Join("/tmp", "hasp-process-"+time.Now().UTC().Format("150405.000000000")+".sock")
	t.Setenv("HASP_SOCKET", socketPath)
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- manager.RunDaemon(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("daemon exited: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for daemon shutdown")
		}
	})
	if err := waitForSocket(manager.SocketPath(), 2*time.Second); err != nil {
		t.Fatalf("wait for socket: %v", err)
	}

	client, err := Dial(context.Background(), manager.SocketPath())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	reply, err := client.OpenSession(context.Background(), OpenSessionRequest{
		HostLabel:    "agent",
		ProjectRoot:  baseDir,
		TTLSeconds:   int(DefaultSessionTTL.Seconds()),
		AgentSafe:    true,
		ConsumerName: "cursor",
	})
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if err := client.RegisterProcess(context.Background(), reply.SessionToken, os.Getpid()); err != nil {
		t.Fatalf("register process: %v", err)
	}
	resolved, err := client.ResolveProcess(context.Background(), os.Getpid())
	if err != nil {
		t.Fatalf("resolve process: %v", err)
	}
	if !resolved.Found || resolved.SessionToken != reply.SessionToken || !resolved.Session.AgentSafe {
		t.Fatalf("unexpected resolve process response %+v", resolved)
	}
}

func TestProcessRegistrationAndLineageEdgeBranches(t *testing.T) {
	lockRuntimeSeams(t)

	store := NewSessionStore()
	store.processIdentity = func(pid int) (string, error) { return "pid-" + strconv.Itoa(pid), nil }
	session, err := store.Open("agent", t.TempDir(), time.Minute, true, "cursor")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if !store.RegisterProcess(session.Token, 12345) {
		t.Fatal("expected process registration")
	}
	store.mu.Lock()
	expired := store.sessions[session.Token]
	expired.ExpiresAt = time.Now().UTC().Add(-time.Second)
	store.sessions[session.Token] = expired
	store.mu.Unlock()
	store.PruneExpired()
	if _, _, ok := store.ResolveProcess(12345); ok {
		t.Fatal("expected expired process mapping to be pruned")
	}

	origParentPID := processParentPID
	defer func() { processParentPID = origParentPID }()
	processParentPID = func(int) (int, error) {
		return 0, errors.New("parent lookup failed")
	}
	if _, err := processParentPID(os.Getpid()); err == nil {
		t.Fatal("expected processParentPID lookup failure")
	}
}

func TestRegisterProcessRejectsChildParentAndSiblingLineage(t *testing.T) {
	lockRuntimeSeams(t)
	origParentPID := processParentPID
	defer func() { processParentPID = origParentPID }()
	processParentPID = func(pid int) (int, error) {
		switch pid {
		case 20, 30:
			return 10, nil
		case 10:
			return 1, nil
		default:
			return 0, nil
		}
	}

	if !peerSharesLineage(10, 20) {
		t.Fatal("expected parent peer to register child request")
	}
	if peerSharesLineage(20, 10) {
		t.Fatal("child peer must not register parent request")
	}
	if peerSharesLineage(20, 30) {
		t.Fatal("sibling peer must not register sibling request")
	}

	broker := &brokerRPC{
		startedAt: time.Now().UTC(),
		sessions:  NewSessionStore(),
		peerPID:   20,
	}
	session, err := broker.sessions.Open("agent", t.TempDir(), time.Minute, true, "mcp")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if err := broker.RegisterProcess(RegisterProcessRequest{SessionToken: session.Token, PID: 10}, &RegisterProcessResponse{}); err == nil {
		t.Fatal("expected child-to-parent registration to be rejected")
	}
	if err := broker.RegisterProcess(RegisterProcessRequest{SessionToken: session.Token, PID: 30}, &RegisterProcessResponse{}); err == nil {
		t.Fatal("expected sibling registration to be rejected")
	}
}

func TestBrokerRPCRegisterAndResolveProcessErrors(t *testing.T) {
	resolved, err := paths.Resolve()
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	// peerPID mirrors what the per-connection serveConn path stamps. With
	// peerPID = os.Getpid(), RegisterProcess(req.PID = os.Getpid()) passes
	// the socket peer-PID gate so the test can exercise the downstream
	// audit-nil / audit-non-nil branches.
	broker := &brokerRPC{
		paths:     resolved,
		startedAt: time.Now().UTC(),
		sessions:  NewSessionStore(),
		peerPID:   uint32(os.Getpid()),
	}
	var registerReply RegisterProcessResponse
	if err := broker.RegisterProcess(RegisterProcessRequest{}, &registerReply); err == nil {
		t.Fatal("expected missing session token error")
	}
	if err := broker.RegisterProcess(RegisterProcessRequest{SessionToken: "token", PID: 0}, &registerReply); err == nil {
		t.Fatal("expected missing pid error")
	}
	if err := broker.RegisterProcess(RegisterProcessRequest{SessionToken: "missing", PID: os.Getpid()}, &registerReply); err == nil {
		t.Fatal("expected missing session registration failure")
	}
	if err := broker.ResolveProcess(ResolveProcessRequest{}, &ResolveProcessResponse{}); err == nil {
		t.Fatal("expected missing pid error")
	}
	var resolveReply ResolveProcessResponse
	if err := broker.ResolveProcess(ResolveProcessRequest{PID: os.Getpid()}, &resolveReply); err != nil {
		t.Fatalf("resolve process without registration: %v", err)
	}
	if resolveReply.Found {
		t.Fatalf("expected unresolved process, got %+v", resolveReply)
	}
	broker.audit = nil
	session, err := broker.sessions.Open("agent", t.TempDir(), time.Minute, true, "claude-code")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if err := broker.RegisterProcess(RegisterProcessRequest{SessionToken: session.Token, PID: os.Getpid()}, &registerReply); err != nil {
		t.Fatalf("register process success with nil audit: %v", err)
	}
	broker.audit, _ = audit.New()
	if err := broker.RegisterProcess(RegisterProcessRequest{SessionToken: session.Token, PID: os.Getpid()}, &registerReply); err != nil {
		t.Fatalf("register process success with audit: %v", err)
	}
}

func TestClientRegisterProcessFailureBranch(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv("HASP_HOME", baseDir)
	socketPath := filepath.Join("/tmp", "hasp-client-"+time.Now().UTC().Format("150405.000000000")+".sock")
	t.Setenv("HASP_SOCKET", socketPath)
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- manager.RunDaemon(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("daemon exited: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for daemon shutdown")
		}
	})
	if err := waitForSocket(manager.SocketPath(), 2*time.Second); err != nil {
		t.Fatalf("wait for socket: %v", err)
	}

	client, err := Dial(context.Background(), manager.SocketPath())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if err := client.RegisterProcess(context.Background(), "missing", os.Getpid()); err == nil {
		t.Fatal("expected register process failure for missing session")
	}
}

func TestResolveProcessNoLineageBranch(t *testing.T) {
	lockRuntimeSeams(t)
	store := NewSessionStore()
	if _, _, ok := store.ResolveProcess(0); ok {
		t.Fatal("expected zero pid resolve to return false")
	}
	origParentPID := processParentPID
	defer func() { processParentPID = origParentPID }()
	processParentPID = func(int) (int, error) { return 0, errors.New("lineage failed") }
	if _, _, ok := store.ResolveProcess(os.Getpid()); ok {
		t.Fatal("expected resolve process failure when lineage lookup fails")
	}
	processParentPID = func(int) (int, error) { return 0, nil }
	if _, _, ok := store.ResolveProcess(os.Getpid()); ok {
		t.Fatal("expected resolve process failure when no process mapping exists")
	}

	session, err := store.Open("agent", t.TempDir(), time.Minute, true, "cursor")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	store.processes[os.Getpid()] = processBinding{token: session.Token, identity: "current"}
	delete(store.sessions, session.Token)
	if _, _, ok := store.ResolveProcess(os.Getpid()); ok {
		t.Fatal("expected resolve process to drop missing session mapping")
	}

	expired, err := store.Open("agent", t.TempDir(), time.Millisecond, true, "cursor")
	if err != nil {
		t.Fatalf("open expiring session: %v", err)
	}
	store.processes[os.Getpid()] = processBinding{token: expired.Token, identity: "current"}
	time.Sleep(5 * time.Millisecond)
	if _, _, ok := store.ResolveProcess(os.Getpid()); ok {
		t.Fatal("expected resolve process to drop expired session mapping")
	}
}

func TestClientRegisterProcessFalseReplyBranch(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	server := rpc.NewServer()
	if err := server.RegisterName("HASP", &FakeHASP{}); err != nil {
		t.Fatalf("register fake server: %v", err)
	}
	go server.ServeCodec(jsonrpc.NewServerCodec(serverConn))

	client := &Client{
		conn:   clientConn,
		client: rpc.NewClientWithCodec(jsonrpc.NewClientCodec(clientConn)),
	}
	if err := client.RegisterProcess(context.Background(), "token", 123); err == nil {
		t.Fatal("expected false reply registration failure")
	}
}

func TestResolveProcessDropsMissingRevokedAndExpiredSessionsAfterIdentityMatch(t *testing.T) {
	lockRuntimeSeams(t)
	origParentPID := processParentPID
	t.Cleanup(func() { processParentPID = origParentPID })
	processParentPID = func(int) (int, error) { return 0, nil }

	now := time.Date(2026, 5, 16, 1, 0, 0, 0, time.UTC)
	store := NewSessionStore()
	store.now = func() time.Time { return now }
	store.processIdentity = func(int) (string, error) { return "identity", nil }

	store.processes[10] = processBinding{token: "missing", identity: "identity"}
	if _, _, ok := store.ResolveProcess(10); ok {
		t.Fatal("missing session should not resolve")
	}

	revokedAt := now.Add(-time.Minute)
	store.sessions["revoked"] = Session{Token: "revoked", ExpiresAt: now.Add(time.Hour), RevokedAt: &revokedAt}
	store.processes[11] = processBinding{token: "revoked", identity: "identity"}
	if _, _, ok := store.ResolveProcess(11); ok {
		t.Fatal("revoked session should not resolve")
	}

	store.sessions["expired"] = Session{Token: "expired", ExpiresAt: now.Add(-time.Minute)}
	store.processes[12] = processBinding{token: "expired", identity: "identity"}
	if _, _, ok := store.ResolveProcess(12); ok {
		t.Fatal("expired session should not resolve")
	}

	store.sessions["blank-identity"] = Session{Token: "blank-identity", ExpiresAt: now.Add(time.Hour)}
	store.processes[13] = processBinding{token: "blank-identity"}
	if _, _, ok := store.ResolveProcess(13); ok {
		t.Fatal("blank process identity binding should not resolve")
	}
}
