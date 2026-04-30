package auditlog

import (
	"errors"
	"os/user"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestHMACKeyDefensiveCopyAndClear(t *testing.T) {
	ClearHMACKey()
	key := []byte("secret")
	SetHMACKey(key)
	key[0] = 'X'
	got := GetHMACKey()
	if string(got) != "secret" {
		t.Fatalf("stored key mutated: %q", string(got))
	}
	got[0] = 'Y'
	if string(GetHMACKey()) != "secret" {
		t.Fatalf("returned key was not defensive copy")
	}
	SetHMACKey(nil)
	if GetHMACKey() != nil {
		t.Fatal("expected nil key after empty set")
	}
	SetHMACKey([]byte("again"))
	ClearHMACKey()
	if GetHMACKey() != nil {
		t.Fatal("expected nil key after clear")
	}
}

func TestAppendAndAppendCLISwallowAuditConstructionFailure(t *testing.T) {
	origNewLog := NewLogFn
	t.Cleanup(func() { NewLogFn = origNewLog })
	NewLogFn = func() (*audit.Log, error) { return nil, errors.New("boom") }

	Append("run", "actor", map[string]any{"k": "v"})
	AppendCLI("run", map[string]any{"k": "v"})
}

func TestAppendWritesWithInstalledKey(t *testing.T) {
	t.Setenv(paths.EnvHome, t.TempDir())
	origNewLog := NewLogFn
	t.Cleanup(func() {
		NewLogFn = origNewLog
		ClearHMACKey()
	})
	NewLogFn = audit.New
	SetHMACKey([]byte("audit-key"))

	Append("run", "actor", map[string]any{"k": "v"})
	log, err := audit.New()
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	events, err := log.WithKey([]byte("audit-key")).Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(events) != 1 || events[0].Actor != "actor" || events[0].Scheme != audit.SchemeHMACSHA256V1 {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestActorLabelFallbacks(t *testing.T) {
	origUser := CurrentUserFn
	t.Cleanup(func() { CurrentUserFn = origUser })

	CurrentUserFn = func() (*user.User, error) { return &user.User{Username: "alice"}, nil }
	if got := ActorLabel(); got != "alice" {
		t.Fatalf("ActorLabel user = %q", got)
	}
	t.Setenv("USER", "fallback")
	CurrentUserFn = func() (*user.User, error) { return nil, errors.New("no user") }
	if got := ActorLabel(); got != "fallback" {
		t.Fatalf("ActorLabel env = %q", got)
	}
	t.Setenv("USER", " ")
	if got := ActorLabel(); got != "unknown" {
		t.Fatalf("ActorLabel unknown = %q", got)
	}
}
