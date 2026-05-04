package gitsafe

// hasp-to7k: BuildCommand must pin LC_ALL=C in the child env so git's
// human-readable error messages stay locale-stable. Today no caller in
// the codebase parses git stderr by content, but bare cmd.Output() still
// captures stderr into *exec.ExitError.Stderr on failure, and any future
// audit/log/wrap site that surfaces those bytes would otherwise vary by
// the operator's LANG. Locking it down is cheap and removes the foot-gun.

import (
	"context"
	"strings"
	"testing"
)

func TestBuildCommandForcesCLocaleForStableGitMessages(t *testing.T) {
	// Even if the parent process runs under a non-C locale, the child must
	// see LC_ALL=C so any git stderr we ever surface is the canonical English.
	t.Setenv("LC_ALL", "fr_FR.UTF-8")
	t.Setenv("LANG", "fr_FR.UTF-8")
	t.Setenv("LC_MESSAGES", "fr_FR.UTF-8")

	cmd := BuildCommand(context.Background(), "/tmp/proj", "rev-parse", "--show-toplevel")

	want := "LC_ALL=C"
	if !envContains(cmd.Env, want) {
		t.Fatalf("BuildCommand env must pin %q; got %v", want, cmd.Env)
	}

	// The parent's LC_ALL must NOT leak — last-wins semantics in Go's exec
	// mean a stray inherited LC_ALL would clobber our pin if it landed later.
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "LC_ALL=") && kv != want {
			t.Fatalf("parent LC_ALL leaked into child env: %q (full env=%v)", kv, cmd.Env)
		}
	}
}
