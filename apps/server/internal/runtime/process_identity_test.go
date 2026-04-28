package runtime

import (
	"os/exec"
	"testing"
	"time"
)

// hasp-sy8: A registered pid identifies a session. If that pid exits and is
// reused by an unrelated process, the new process must NOT inherit the old
// session — that's the lineage-spoof attack the bead calls out. We probe a
// per-process identity token (start time on Linux/Darwin) at registration,
// then re-probe at resolution; on mismatch the binding is dropped.

func TestSessionStoreResolveProcessRejectsPIDReuse(t *testing.T) {
	lockRuntimeSeams(t)

	identities := map[int]string{42: "alpha"}
	origLineage := lineageExecCommand
	t.Cleanup(func() { lineageExecCommand = origLineage })
	lineageExecCommand = func(_ string, _ ...string) *exec.Cmd {
		// ppid=0 → processLineage stops at the input pid alone.
		return exec.Command("sh", "-c", "printf '0\\n'")
	}

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

func TestSessionStoreResolveProcessAdvisoryWhenIdentityProbeFails(t *testing.T) {
	lockRuntimeSeams(t)

	origLineage := lineageExecCommand
	t.Cleanup(func() { lineageExecCommand = origLineage })
	lineageExecCommand = func(_ string, _ ...string) *exec.Cmd {
		return exec.Command("sh", "-c", "printf '0\\n'")
	}

	store := NewSessionStore()
	store.processIdentity = func(pid int) (string, error) {
		return "", nil // probe unsupported on this platform
	}
	session, err := store.Open("agent", t.TempDir(), time.Minute, true, "claude-code")
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if !store.RegisterProcess(session.Token, 99) {
		t.Fatal("register process")
	}
	// When the identity probe returns "" at register and at resolve, ancestry
	// remains advisory — resolution still works (no false denials on platforms
	// without a probe).
	if _, _, ok := store.ResolveProcess(99); !ok {
		t.Fatal("expected resolve to succeed when identity probe is unsupported")
	}
}
