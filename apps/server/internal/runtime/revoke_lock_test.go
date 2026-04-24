package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

type revokeAllLockRPC struct{}

func (revokeAllLockRPC) RevokeAllSessions(_ RevokeAllSessionsRequest, reply *RevokeAllSessionsResponse) error {
	*reply = RevokeAllSessionsResponse{RevokedCount: 2}
	return nil
}

func (revokeAllLockRPC) LockVault(_ LockVaultRequest, reply *LockVaultResponse) error {
	*reply = LockVaultResponse{RevokedCount: 3, Locked: true}
	return nil
}

func TestClientRevokeAllSessionsAndLockVault(t *testing.T) {
	socketPath, cleanup := serveRuntimeRPC(t, revokeAllLockRPC{})
	defer cleanup()
	client, err := Dial(context.Background(), socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	revoked, err := client.RevokeAllSessions(context.Background())
	if err != nil || revoked.RevokedCount != 2 {
		t.Fatalf("revoke all = %+v err=%v", revoked, err)
	}
	locked, err := client.LockVault(context.Background())
	if err != nil || !locked.Locked || locked.RevokedCount != 3 {
		t.Fatalf("lock vault = %+v err=%v", locked, err)
	}
}

func TestBrokerRevokeAllSessionsAndLockVault(t *testing.T) {
	sessions := NewSessionStore()
	if _, err := sessions.Open("agent-a", "", time.Minute, false, ""); err != nil {
		t.Fatalf("open a: %v", err)
	}
	if _, err := sessions.Open("agent-b", "", time.Minute, false, ""); err != nil {
		t.Fatalf("open b: %v", err)
	}
	snapshot := sessions.Snapshot()
	if len(snapshot) == 0 {
		t.Fatal("expected sessions before process registration")
	}
	if !sessions.RegisterProcess(snapshot[0].Token, 1234) {
		t.Fatalf("register process for %s", snapshot[0].Token)
	}
	broker := &brokerRPC{paths: paths.Paths{SocketPath: "/tmp/hasp.sock"}, startedAt: time.Now().UTC(), sessions: sessions, auditState: newAuditState(nil)}
	var revokeReply RevokeAllSessionsResponse
	if err := broker.RevokeAllSessions(RevokeAllSessionsRequest{}, &revokeReply); err != nil {
		t.Fatalf("revoke all: %v", err)
	}
	if revokeReply.RevokedCount != 2 || sessions.ActiveCount() != 0 {
		t.Fatalf("unexpected revoke result %+v active=%d", revokeReply, sessions.ActiveCount())
	}
	if _, err := sessions.Open("agent-c", "", time.Minute, false, ""); err != nil {
		t.Fatalf("open c: %v", err)
	}
	var lockReply LockVaultResponse
	if err := broker.LockVault(LockVaultRequest{}, &lockReply); err != nil {
		t.Fatalf("lock vault: %v", err)
	}
	if !lockReply.Locked || lockReply.RevokedCount != 1 || sessions.ActiveCount() != 0 {
		t.Fatalf("unexpected lock result %+v active=%d", lockReply, sessions.ActiveCount())
	}
}

func TestSessionStoreIdleExpiryAndDisabledIdle(t *testing.T) {
	now := time.Date(2026, 4, 23, 8, 0, 0, 0, time.UTC)
	store := NewSessionStore()
	store.now = func() time.Time { return now }
	store.idleTTL = time.Minute
	session, err := store.Open("agent", "", time.Hour, false, "")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, ok := store.Resolve(session.Token); ok {
		t.Fatal("expected idle-expired session")
	}
	store.idleTTL = 0
	session, err = store.Open("agent", "", time.Hour, false, "")
	if err != nil {
		t.Fatalf("open second session: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, ok := store.Resolve(session.Token); !ok {
		t.Fatal("expected disabled idle expiry to keep session active")
	}
}
