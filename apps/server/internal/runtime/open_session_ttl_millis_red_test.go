package runtime

import (
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

// hasp-4xf9: integration tests that exercise the session-expiry rejection
// path used to time.Sleep(2*time.Second) waiting for a TTL=1s session.
// OpenSessionRequest.TTLMillis lets them request a sub-second TTL so the
// test only needs to sleep ~100ms.

func TestOpenSession_TTLMillisHonoured(t *testing.T) {
	resolved, err := paths.Resolve()
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	fixedNow := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	store := NewSessionStore()
	store.now = func() time.Time { return fixedNow }
	broker := &brokerRPC{
		paths:     resolved,
		startedAt: fixedNow,
		sessions:  store,
	}
	var reply OpenSessionResponse
	if err := broker.OpenSession(OpenSessionRequest{
		HostLabel:   "agent",
		ProjectRoot: "/tmp/project",
		TTLMillis:   50,
	}, &reply); err != nil {
		t.Fatalf("open session: %v", err)
	}
	if got := reply.ExpiresAt.Sub(fixedNow); got != 50*time.Millisecond {
		t.Fatalf("TTLMillis=50 produced ExpiresAt %v after now; want 50ms", got)
	}
}

func TestOpenSession_TTLMillisTakesPrecedenceOverSeconds(t *testing.T) {
	resolved, err := paths.Resolve()
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	fixedNow := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	store := NewSessionStore()
	store.now = func() time.Time { return fixedNow }
	broker := &brokerRPC{
		paths:     resolved,
		startedAt: fixedNow,
		sessions:  store,
	}
	var reply OpenSessionResponse
	if err := broker.OpenSession(OpenSessionRequest{
		HostLabel:   "agent",
		ProjectRoot: "/tmp/project",
		TTLMillis:   75,
		TTLSeconds:  600,
	}, &reply); err != nil {
		t.Fatalf("open session: %v", err)
	}
	if got := reply.ExpiresAt.Sub(fixedNow); got != 75*time.Millisecond {
		t.Fatalf("TTLMillis should take precedence over TTLSeconds; got %v after now, want 75ms", got)
	}
}

func TestOpenSession_TTLSecondsStillHonouredWhenMillisZero(t *testing.T) {
	resolved, err := paths.Resolve()
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	fixedNow := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	store := NewSessionStore()
	store.now = func() time.Time { return fixedNow }
	broker := &brokerRPC{
		paths:     resolved,
		startedAt: fixedNow,
		sessions:  store,
	}
	var reply OpenSessionResponse
	if err := broker.OpenSession(OpenSessionRequest{
		HostLabel:   "agent",
		ProjectRoot: "/tmp/project",
		TTLSeconds:  60,
	}, &reply); err != nil {
		t.Fatalf("open session: %v", err)
	}
	if got := reply.ExpiresAt.Sub(fixedNow); got != 60*time.Second {
		t.Fatalf("TTLSeconds=60 should still produce 60s TTL; got %v", got)
	}
}
