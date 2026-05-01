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

// daemonStartupTimeout caps how long EnsureDaemon waits for a freshly-spawned
// daemon to bind its socket and pass verifyDaemon. The previous 5-second
// budget was tight on cold launchd start with a Keychain unlock prompt
// (the user has to physically click "Allow"), and on first run after a
// reboot when argon2id KDF parameters are sized aggressively. 15s gives
// the daemon room for both without silently turning a slow start into a
// hard failure that requires a retry.
const daemonStartupTimeout = 15 * time.Second

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
	deadline := time.Now().Add(daemonStartupTimeout)
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
	// peerUID and peerPID are the peer-credential lookups. Production
	// builds wire them to realPeerUID / realPeerPID via newRPCServer; tests
	// override them locally on a server instance instead of swapping
	// package-level vars under a global mutex.
	peerUID func(net.Conn) (uint32, error)
	peerPID func(net.Conn) (uint32, error)
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
		peerUID:    realPeerUID,
		peerPID:    realPeerPID,
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

// serve is the daemon's RPC accept loop. The trust boundary for the daemon
// is a peer-UID check on every Accept: socket-file mode 0o600 alone does not
// protect against same-UID processes dialing the socket, so we verify the
// connecting peer's effective UID via SO_PEERCRED (Linux) / LOCAL_PEERCRED
// (Darwin) and fail closed on mismatch or lookup failure.
func (s *rpcServer) serve(ctx context.Context, listener net.Listener) error {
	expectedUID := uint32(os.Geteuid())
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

		peerUID, peerErr := s.peerUID(conn)
		if peerErr != nil {
			_ = conn.Close()
			s.appendPeerRejectAudit(map[string]any{
				"action": "peer.reject",
				"reason": "lookup_failed",
				"error":  peerErr.Error(),
			})
			continue
		}
		if peerUID != expectedUID {
			_ = conn.Close()
			s.appendPeerRejectAudit(map[string]any{
				"action":       "peer.reject",
				"reason":       "mismatched_uid",
				"peer_uid":     peerUID,
				"expected_uid": expectedUID,
			})
			continue
		}

		// Capture peer PID per-connection. s.peerPID errors are NOT a hard
		// reject at accept (some platforms / kernels may not surface PID even
		// when UID is fine) — instead we stamp peerPID = 0, which makes
		// privileged operations like RegisterProcess fail closed inside the
		// handler. Read-only RPCs (Ping/Status) still work.
		peerPID, pidErr := s.peerPID(conn)
		if pidErr != nil {
			peerPID = 0
		}

		go s.serveConn(conn, peerPID)
	}
}

func (s *rpcServer) serveConn(conn net.Conn, peerPID uint32) {
	perConn := rpc.NewServer()
	bound := &brokerRPC{
		paths:      s.paths,
		startedAt:  s.startedAt,
		sessions:   s.sessions,
		audit:      s.audit,
		auditState: s.auditState,
		peerPID:    peerPID,
	}
	if err := registerServerName(perConn, "HASP", bound); err != nil {
		_ = conn.Close()
		return
	}
	perConn.ServeCodec(jsonrpc.NewServerCodec(conn))
}

func (s *rpcServer) stop() {
	s.stopOnce.Do(func() {
		s.sessions.PruneExpired()
	})
}

// appendPeerRejectAudit records a peer rejection audit event. It guards for a
// nil audit logger so that rejection is still fail-closed even when the audit
// subsystem failed to initialise.
func (s *rpcServer) appendPeerRejectAudit(details map[string]any) {
	if s.audit == nil {
		s.auditState.RecordAppendResult(errors.New("audit logger unavailable"))
		return
	}
	_, err := s.audit.Append(audit.EventDeny, "daemon", details)
	s.auditState.RecordAppendResult(err)
}

type brokerRPC struct {
	paths      paths.Paths
	startedAt  time.Time
	sessions   *SessionStore
	audit      *audit.Log
	auditState *AuditState
	// peerPID is the PID of the unix-socket peer for this connection, captured
	// at accept time via SO_PEERCRED / LOCAL_PEERPID. Zero means "unknown" —
	// either the lookup failed or this brokerRPC was registered on the shared
	// rpc.Server (legacy/template path). Privileged operations that depend on
	// peer identity (RegisterProcess) fail closed when peerPID is zero.
	peerPID uint32
}

func (b *brokerRPC) Ping(_ PingRequest, reply *PingResponse) error {
	*reply = PingResponse{
		Name:       "hasp",
		Version:    VersionString(),
		ServerTime: time.Now().UTC(),
	}
	return nil
}

func (b *brokerRPC) Status(_ StatusRequest, reply *StatusResponse) error {
	auditDegraded, degradedAt := b.auditState.Snapshot()
	processIdentityDegraded, processIdentityReason := b.sessions.ProcessIdentityDegraded()
	*reply = StatusResponse{
		SocketPath:                    b.paths.SocketPath,
		PID:                           os.Getpid(),
		StartedAt:                     b.startedAt,
		ActiveSessions:                b.sessions.ActiveCount(),
		Sessions:                      b.sessions.ViewSnapshot(),
		AuditDegraded:                 auditDegraded,
		AuditDegradedAt:               degradedAt,
		ProcessIdentityDegraded:       processIdentityDegraded,
		ProcessIdentityDegradedReason: processIdentityReason,
	}
	return nil
}

func (b *brokerRPC) OpenSession(req OpenSessionRequest, reply *OpenSessionResponse) error {
	if req.HostLabel == "" {
		return errors.New("host_label is required")
	}
	var ttl time.Duration
	if req.TTLMillis > 0 {
		ttl = time.Duration(req.TTLMillis) * time.Millisecond
	} else {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
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
	// Socket peer-PID validation: the kernel-attested socket peer must be
	// either req.PID itself (self-registration) OR an ancestor of req.PID
	// (parent registering a child it spawned — `hasp agent launch` flow).
	// Same-uid file permissions alone don't stop a neighbouring process from
	// binding a session to an arbitrary target PID; the lineage gate does.
	// peerPID == 0 means "unknown" (lookup failed or brokerRPC isn't bound to
	// a connection); fail closed.
	if b.peerPID == 0 {
		b.appendAudit(audit.EventDeny, "daemon", map[string]any{
			"action": "session.process.register.reject",
			"reason": "unknown_peer_pid",
			"pid":    req.PID,
		})
		return errors.New("peer pid unavailable; refusing to bind session to caller-supplied pid")
	}
	if !peerSharesLineage(b.peerPID, req.PID) {
		b.appendAudit(audit.EventDeny, "daemon", map[string]any{
			"action":   "session.process.register.reject",
			"reason":   "peer_not_in_lineage",
			"req_pid":  req.PID,
			"peer_pid": b.peerPID,
		})
		return fmt.Errorf("pid lineage mismatch: socket peer PID=%d shares no lineage with req.PID=%d", b.peerPID, req.PID)
	}
	registered := b.sessions.RegisterProcess(req.SessionToken, req.PID)
	*reply = RegisterProcessResponse{Registered: registered}
	if !registered {
		return errors.New("session not found")
	}
	b.appendAudit(audit.EventApprove, "daemon", map[string]any{"action": "session.process.register", "pid": req.PID})
	return nil
}

// peerSharesLineage reports whether the kernel-attested socket peer and
// reqPID share a parent-chain relationship in either direction. Self
// (peerPID == reqPID), peer-as-ancestor-of-req (parent registers spawned
// child), and req-as-ancestor-of-peer (child MCP registers its parent — the
// `hasp agent mcp` flow registers os.Getppid()) are all valid trust paths.
// Any other PID — a sibling, an unrelated same-uid process, or an arbitrary
// PID picked by an attacker — is denied.
func peerSharesLineage(peerPID uint32, reqPID int) bool {
	if peerPID == 0 || reqPID <= 0 {
		return false
	}
	if uint32(reqPID) == peerPID {
		return true
	}
	if reqLineage, err := processLineage(reqPID); err == nil {
		for _, ancestor := range reqLineage {
			if uint32(ancestor) == peerPID {
				return true
			}
		}
	}
	if peerLineage, err := processLineage(int(peerPID)); err == nil {
		for _, ancestor := range peerLineage {
			if ancestor == reqPID {
				return true
			}
		}
	}
	return false
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
