package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
)

type Manager struct {
	paths paths.Paths
}

var spawnDaemonProcess = startDetachedProcess
var (
	resolveRuntimePaths = paths.Resolve
	registerServerName  = func(server *rpc.Server, name string, rcvr any) error { return server.RegisterName(name, rcvr) }
	runtimeMkdirAll     = os.MkdirAll
	runtimeRemove       = os.Remove
	listenUnix          = net.Listen
	writeFile           = os.WriteFile
	chmodFile           = os.Chmod
	newRuntimeAuditLog  = audit.New
)

func NewManager() (*Manager, error) {
	resolved, err := resolveRuntimePaths()
	if err != nil {
		return nil, err
	}
	return &Manager{paths: resolved}, nil
}

func (m *Manager) SocketPath() string {
	return m.paths.SocketPath
}

func (m *Manager) EnsureDaemon(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := runtimeMkdirAll(m.paths.RuntimeDir, 0o700); err != nil {
		return fmt.Errorf("create runtime dir: %w", err)
	}
	if client, err := Dial(ctx, m.paths.SocketPath); err == nil {
		ok := verifyDaemon(ctx, client, m.paths.SocketPath)
		_ = client.Close()
		if ok {
			return nil
		}
	}
	if err := runtimeRemove(m.paths.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove untrusted socket: %w", err)
	}
	if err := spawnDaemonProcess(ctx); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		client, err := Dial(ctx, m.paths.SocketPath)
		if err == nil {
			ok := verifyDaemon(ctx, client, m.paths.SocketPath)
			_ = client.Close()
			if ok {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("timed out waiting for hasp daemon")
}

func verifyDaemon(ctx context.Context, client *Client, socketPath string) bool {
	ping, err := client.Ping(ctx)
	if err != nil || ping.Name != "hasp" {
		return false
	}
	status, err := client.Status(ctx)
	if err != nil {
		return false
	}
	return status.SocketPath == socketPath && status.PID > 0
}

func (m *Manager) StartDaemon(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return spawnDaemonProcess(ctx)
}

func (m *Manager) StopDaemon() error {
	return stopDetachedProcess()
}

func (m *Manager) RunDaemon(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := runtimeMkdirAll(m.paths.RuntimeDir, 0o700); err != nil {
		return fmt.Errorf("create runtime dir: %w", err)
	}
	if err := removeStaleSocket(m.paths.SocketPath); err != nil {
		return err
	}
	listener, err := listenUnix("unix", m.paths.SocketPath)
	if err != nil {
		return fmt.Errorf("listen on socket: %w", err)
	}
	defer func() {
		_ = listener.Close()
		_ = runtimeRemove(m.paths.SocketPath)
	}()
	if err := chmodFile(m.paths.SocketPath, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	if err := writeFile(m.paths.PidFilePath, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}
	defer func() {
		_ = runtimeRemove(m.paths.PidFilePath)
	}()

	server := newRPCServer(m.paths)
	if err := server.register(); err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.serve(ctx, listener)
	}()

	select {
	case <-ctx.Done():
		server.stop()
		return nil
	case err := <-errCh:
		return err
	}
}

type rpcServer struct {
	startedAt  time.Time
	paths      paths.Paths
	server     *rpc.Server
	sessions   *SessionStore
	audit      *audit.Log
	auditState *AuditState
	stopOnce   sync.Once
}

func newRPCServer(runtimePaths paths.Paths) *rpcServer {
	startedAt := time.Now().UTC()
	log, logErr := newRuntimeAuditLog()
	auditState := newAuditState(nil)
	if logErr != nil {
		auditState.MarkDegradedAt(startedAt)
	}
	return &rpcServer{
		startedAt:  startedAt,
		paths:      runtimePaths,
		server:     rpc.NewServer(),
		sessions:   NewSessionStore(),
		audit:      log,
		auditState: auditState,
	}
}

func (s *rpcServer) register() error {
	return registerServerName(s.server, "HASP", &brokerRPC{
		paths:      s.paths,
		startedAt:  s.startedAt,
		sessions:   s.sessions,
		audit:      s.audit,
		auditState: s.auditState,
	})
}

func (s *rpcServer) serve(ctx context.Context, listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}
		go s.server.ServeCodec(jsonrpc.NewServerCodec(conn))
	}
}

func (s *rpcServer) stop() {
	s.stopOnce.Do(func() {
		s.sessions.PruneExpired()
	})
}

type brokerRPC struct {
	paths      paths.Paths
	startedAt  time.Time
	sessions   *SessionStore
	audit      *audit.Log
	auditState *AuditState
}

func (b *brokerRPC) Ping(_ PingRequest, reply *PingResponse) error {
	*reply = PingResponse{
		Name:       "hasp",
		Version:    Version(),
		ServerTime: time.Now().UTC(),
	}
	return nil
}

func (b *brokerRPC) Status(_ StatusRequest, reply *StatusResponse) error {
	auditDegraded, degradedAt := b.auditState.Snapshot()
	*reply = StatusResponse{
		SocketPath:      b.paths.SocketPath,
		PID:             os.Getpid(),
		StartedAt:       b.startedAt,
		ActiveSessions:  b.sessions.ActiveCount(),
		Sessions:        b.sessions.ViewSnapshot(),
		AuditDegraded:   auditDegraded,
		AuditDegradedAt: degradedAt,
	}
	return nil
}

func (b *brokerRPC) OpenSession(req OpenSessionRequest, reply *OpenSessionResponse) error {
	if req.HostLabel == "" {
		return errors.New("host_label is required")
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 || ttl > DefaultSessionTTL {
		ttl = DefaultSessionTTL
	}
	session, err := b.sessions.Open(req.HostLabel, req.ProjectRoot, ttl, req.AgentSafe, req.ConsumerName)
	if err != nil {
		return err
	}
	*reply = OpenSessionResponse{
		SessionID:    session.ID,
		SessionToken: session.Token,
		LocalUser:    session.LocalUser,
		HostLabel:    session.HostLabel,
		ProjectRoot:  session.ProjectRoot,
		AgentSafe:    session.AgentSafe,
		ConsumerName: session.ConsumerName,
		LastSeenAt:   session.LastSeenAt,
		ExpiresAt:    session.ExpiresAt,
	}
	b.appendAudit(audit.EventApprove, "daemon", map[string]any{
		"action":        "session.open",
		"host_label":    session.HostLabel,
		"project_root":  session.ProjectRoot,
		"agent_safe":    session.AgentSafe,
		"consumer_name": session.ConsumerName,
	})
	return nil
}

func (b *brokerRPC) ResolveSession(req ResolveSessionRequest, reply *ResolveSessionResponse) error {
	if req.SessionToken == "" {
		return errors.New("session_token is required")
	}
	session, ok := b.sessions.Resolve(req.SessionToken)
	if !ok {
		return errors.New("session not found")
	}
	*reply = ResolveSessionResponse{Session: session.View()}
	return nil
}

func (b *brokerRPC) RevokeSession(req RevokeSessionRequest, reply *RevokeSessionResponse) error {
	if req.SessionToken == "" {
		return errors.New("session_token is required")
	}
	session, _ := b.sessions.Resolve(req.SessionToken)
	revoked := b.sessions.Revoke(req.SessionToken)
	*reply = RevokeSessionResponse{Revoked: revoked}
	if revoked {
		b.appendAudit(audit.EventDeny, "daemon", map[string]any{"action": "session.revoke", "session_id": session.ID})
	}
	return nil
}

func (b *brokerRPC) RevokeAllSessions(_ RevokeAllSessionsRequest, reply *RevokeAllSessionsResponse) error {
	revoked := b.sessions.RevokeAll()
	*reply = RevokeAllSessionsResponse{RevokedCount: len(revoked)}
	b.appendAudit(audit.EventDeny, "daemon", map[string]any{"action": "session.revoke_all", "revoked_count": len(revoked)})
	return nil
}

func (b *brokerRPC) LockVault(_ LockVaultRequest, reply *LockVaultResponse) error {
	revoked := b.sessions.RevokeAll()
	*reply = LockVaultResponse{RevokedCount: len(revoked), Locked: true}
	b.appendAudit(audit.EventDeny, "daemon", map[string]any{"action": "vault.lock", "revoked_count": len(revoked)})
	return nil
}

func (b *brokerRPC) RegisterProcess(req RegisterProcessRequest, reply *RegisterProcessResponse) error {
	if req.SessionToken == "" {
		return errors.New("session_token is required")
	}
	if req.PID <= 0 {
		return errors.New("pid is required")
	}
	registered := b.sessions.RegisterProcess(req.SessionToken, req.PID)
	*reply = RegisterProcessResponse{Registered: registered}
	if !registered {
		return errors.New("session not found")
	}
	b.appendAudit(audit.EventApprove, "daemon", map[string]any{"action": "session.process.register", "pid": req.PID})
	return nil
}

func (b *brokerRPC) appendAudit(eventType string, actor string, details map[string]any) {
	if b.audit == nil {
		b.auditState.RecordAppendResult(errors.New("audit logger unavailable"))
		return
	}
	_, err := b.audit.Append(eventType, actor, details)
	b.auditState.RecordAppendResult(err)
}

func (b *brokerRPC) ResolveProcess(req ResolveProcessRequest, reply *ResolveProcessResponse) error {
	if req.PID <= 0 {
		return errors.New("pid is required")
	}
	session, token, ok := b.sessions.ResolveProcess(req.PID)
	if !ok {
		*reply = ResolveProcessResponse{Found: false}
		return nil
	}
	*reply = ResolveProcessResponse{
		Found:        true,
		SessionToken: token,
		Session:      session.View(),
	}
	return nil
}

func removeStaleSocket(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat socket path: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket file at %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	return nil
}
