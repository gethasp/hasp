package runtime

import (
	"errors"
	"testing"
	"time"
)

// hasp-sy8: A registered pid identifies a process binding. If that pid exits
// and is reused by an unrelated process, the new process must NOT inherit the
// old session. We probe a per-process stale-binding token (start time on
// Linux/Darwin) at registration, then re-probe at resolution; on mismatch,
// failure, or unavailability, the binding is dropped.

func TestSessionStoreResolveProcessRejectsPIDReuse(t *testing.T) {
	lockRuntimeSeams(t)

	identities := map[int]string{42: "alpha"}
	origParentPID := processParentPID
	t.Cleanup(func() { processParentPID = origParentPID })
	processParentPID = func(int) (int, error) { return 0, nil }

	store := NewSessionStore()
	store.processIdentity = func(pid int) (string, error) {
		return identities[pid], nil
	}
	session, err := store.Open("agent", t.TempDir(), time.Minute, true, "claude-code")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if !store.RegisterProcess(session.Token, 42) {
		t.Fatal("register process")
	}
	if _, _, ok := store.ResolveProcess(42); !ok {
		t.Fatal("expected resolve to succeed when identity matches")
	}

	// Simulate PID reuse: same pid number, different process identity.
	identities[42] = "beta"
	if _, _, ok := store.ResolveProcess(42); ok {
		t.Fatal("expected resolve to fail after pid reuse (identity changed)")
	}
	// Reverting the identity must not revive the dropped binding.
	identities[42] = "alpha"
	if _, _, ok := store.ResolveProcess(42); ok {
		t.Fatal("expected binding to stay dropped after pid-reuse rejection")
	}
}

func TestSessionStoreRegisterProcessFailsClosedWhenIdentityProbeUnavailable(t *testing.T) {
	lockRuntimeSeams(t)

	origParentPID := processParentPID
	t.Cleanup(func() { processParentPID = origParentPID })
	processParentPID = func(int) (int, error) { return 0, nil }

	store := NewSessionStore()
	store.processIdentity = func(pid int) (string, error) {
		return "", nil // probe unsupported on this platform
	}
	session, err := store.Open("agent", t.TempDir(), time.Minute, true, "claude-code")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if store.RegisterProcess(session.Token, 99) {
		t.Fatal("expected register to fail closed when identity probe is unsupported")
	}
	if _, _, ok := store.ResolveProcess(99); ok {
		t.Fatal("expected resolve to fail when identity probe is unsupported")
	}
	degraded, reason := store.ProcessIdentityDegraded()
	if !degraded || reason == "" {
		t.Fatalf("expected identity degradation to be surfaced, got degraded=%t reason=%q", degraded, reason)
	}
}

func TestSessionStoreProcessIdentityDegradationBranches(t *testing.T) {
	lockRuntimeSeams(t)

	origParentPID := processParentPID
	t.Cleanup(func() { processParentPID = origParentPID })
	processParentPID = func(int) (int, error) { return 0, nil }

	t.Run("register probe error", func(t *testing.T) {
		store := NewSessionStore()
		store.processIdentity = func(int) (string, error) {
			return "", errors.New("probe failed")
		}
		session, err := store.Open("agent", t.TempDir(), time.Minute, true, "claude-code")
		if err != nil {
			t.Fatalf("open session: %v", err)
		}
		if store.RegisterProcess(session.Token, 77) {
			t.Fatal("expected register process to fail closed")
		}
		degraded, reason := store.ProcessIdentityDegraded()
		if !degraded || reason == "" {
			t.Fatalf("expected register degradation, got degraded=%t reason=%q", degraded, reason)
		}
	})

	t.Run("resolve recheck error", func(t *testing.T) {
		store := NewSessionStore()
		identityErr := false
		store.processIdentity = func(int) (string, error) {
			if identityErr {
				return "", errors.New("recheck failed")
			}
			return "alpha", nil
		}
		session, err := store.Open("agent", t.TempDir(), time.Minute, true, "claude-code")
		if err != nil {
			t.Fatalf("open session: %v", err)
		}
		if !store.RegisterProcess(session.Token, 88) {
			t.Fatal("register process")
		}
		identityErr = true
		if _, _, ok := store.ResolveProcess(88); ok {
			t.Fatal("expected resolve to fail closed on recheck error")
		}
		degraded, reason := store.ProcessIdentityDegraded()
		if !degraded || reason == "" {
			t.Fatalf("expected resolve degradation, got degraded=%t reason=%q", degraded, reason)
		}
	})

	t.Run("resolve recheck unavailable", func(t *testing.T) {
		store := NewSessionStore()
		currentIdentity := "alpha"
		store.processIdentity = func(int) (string, error) {
			return currentIdentity, nil
		}
		session, err := store.Open("agent", t.TempDir(), time.Minute, true, "claude-code")
		if err != nil {
			t.Fatalf("open session: %v", err)
		}
		if !store.RegisterProcess(session.Token, 99) {
			t.Fatal("register process")
		}
		currentIdentity = ""
		if _, _, ok := store.ResolveProcess(99); ok {
			t.Fatal("expected resolve to fail closed when recheck is unavailable")
		}
		degraded, reason := store.ProcessIdentityDegraded()
		if !degraded || reason == "" {
			t.Fatalf("expected unavailable degradation, got degraded=%t reason=%q", degraded, reason)
		}
	})
}
