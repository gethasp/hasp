package runtime

import (
	"context"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"os/exec"
	"path/filepath"
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
	defer cancel()
	go func() { _ = manager.RunDaemon(ctx) }()
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

	origLineage := lineageExecCommand
	defer func() { lineageExecCommand = origLineage }()
	lineageExecCommand = func(string, ...string) *exec.Cmd {
		return exec.Command("/definitely-missing-ps-binary")
	}
	if _, err := processParentPID(os.Getpid()); err == nil {
		t.Fatal("expected processParentPID command failure")
	}
	lineageExecCommand = func(string, ...string) *exec.Cmd {
		return exec.Command("sh", "-c", "printf 'not-a-pid'")
	}
	if _, err := processParentPID(os.Getpid()); err == nil {
		t.Fatal("expected processParentPID parse failure")
	}
}

func TestBrokerRPCRegisterAndResolveProcessErrors(t *testing.T) {
	resolved, err := paths.Resolve()
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	broker := &brokerRPC{
		paths:     resolved,
		startedAt: time.Now().UTC(),
		sessions:  NewSessionStore(),
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
	if err := broker.RegisterProcess(RegisterProcessRequest{SessionToken: session.Token, PID: os.Getpid() + 1}, &registerReply); err != nil {
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
	defer cancel()
	go func() { _ = manager.RunDaemon(ctx) }()
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
	origExec := lineageExecCommand
	defer func() { lineageExecCommand = origExec }()
	lineageExecCommand = func(string, ...string) *exec.Cmd {
		return exec.Command("sh", "-c", "exit 1")
	}
	if _, _, ok := store.ResolveProcess(os.Getpid()); ok {
		t.Fatal("expected resolve process failure when lineage lookup fails")
	}
	lineageExecCommand = func(_ string, args ...string) *exec.Cmd {
		return exec.Command("sh", "-c", "printf '0'")
	}
	if _, _, ok := store.ResolveProcess(os.Getpid()); ok {
		t.Fatal("expected resolve process failure when no process mapping exists")
	}

	session, err := store.Open("agent", t.TempDir(), time.Minute, true, "cursor")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	store.processes[os.Getpid()] = session.Token
	delete(store.sessions, session.Token)
	if _, _, ok := store.ResolveProcess(os.Getpid()); ok {
		t.Fatal("expected resolve process to drop missing session mapping")
	}

	expired, err := store.Open("agent", t.TempDir(), time.Millisecond, true, "cursor")
	if err != nil {
		t.Fatalf("open expiring session: %v", err)
	}
	store.processes[os.Getpid()] = expired.Token
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
