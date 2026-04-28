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
	broker := &brokerRPC{
		paths:     resolved,
		startedAt: time.Now().UTC(),
		sessions:  NewSessionStore(),
	}
	var reply OpenSessionResponse
	if err := broker.OpenSession(OpenSessionRequest{
		HostLabel:   "agent",
		ProjectRoot: "/tmp/project",
		TTLMillis:   50,
	}, &reply); err != nil {
		t.Fatalf("open session: %v", err)
	}
	got := reply.ExpiresAt.Sub(time.Now().UTC())
	if got > 200*time.Millisecond {
		t.Fatalf("TTLMillis=50 produced ExpiresAt %v in the future; expected <200ms", got)
	}
	if got < 0 {
		t.Fatalf("TTLMillis=50 produced ExpiresAt already in the past: %v", got)
	}
}

func TestOpenSession_TTLMillisTakesPrecedenceOverSeconds(t *testing.T) {
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
		TTLMillis:   75,
		TTLSeconds:  600,
	}, &reply); err != nil {
		t.Fatalf("open session: %v", err)
	}
	got := reply.ExpiresAt.Sub(time.Now().UTC())
	if got > 250*time.Millisecond {
		t.Fatalf("TTLMillis should take precedence over TTLSeconds; got ExpiresAt %v in the future", got)
	}
}

func TestOpenSession_TTLSecondsStillHonouredWhenMillisZero(t *testing.T) {
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
		TTLSeconds:  60,
	}, &reply); err != nil {
		t.Fatalf("open session: %v", err)
	}
	got := reply.ExpiresAt.Sub(time.Now().UTC())
	if got < 50*time.Second || got > 65*time.Second {
		t.Fatalf("TTLSeconds=60 should still produce ~60s TTL; got %v", got)
	}
}
