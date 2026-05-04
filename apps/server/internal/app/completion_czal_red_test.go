package app

// hasp-czal: completion scripts must descend past root level. Bash only handled
// COMP_CWORD<=2 with a hardcoded 'secret' branch; zsh likewise; fish and
// powershell completed only the root word. This test pins the contract: every
// shell script delegates nested completion to a single in-binary entry point
// (`hasp __complete`) so the dispatcher stays the single source of truth.

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// TestCompletionCzalBashScriptDelegatesToBinary verifies the bash script
// invokes `hasp __complete` (or equivalent) so depth>=2 completion works
// for every subcommand, not just `secret`.
func TestCompletionCzalBashScriptDelegatesToBinary(t *testing.T) {
	script, err := RenderBashCompletionScript()
	if err != nil {
		t.Fatalf("RenderBashCompletionScript: %v", err)
	}
	if !strings.Contains(script, "__complete") {
		t.Fatalf("bash script must delegate to `hasp __complete` for nested completion; got:\n%s", script)
	}
	// Hard-coded `case "$prev" in secret)` was the broken-by-design pattern.
	// If we still see it, we never actually fixed the root cause.
	if strings.Contains(script, "secret)\n") && !strings.Contains(script, "$@") && !strings.Contains(script, "${COMP_WORDS[@]:1}") {
		t.Fatalf("bash script still hard-codes per-subcommand cases; should pass remaining words to `hasp __complete`:\n%s", script)
	}
}

// TestCompletionCzalZshScriptDelegatesToBinary verifies zsh dispatches via the
// in-binary completion entry point.
func TestCompletionCzalZshScriptDelegatesToBinary(t *testing.T) {
	script, err := RenderZshCompletionScript()
	if err != nil {
		t.Fatalf("RenderZshCompletionScript: %v", err)
	}
	if !strings.Contains(script, "__complete") {
		t.Fatalf("zsh script must delegate to `hasp __complete` for nested completion; got:\n%s", script)
	}
}

// TestCompletionCzalFishScriptDescends verifies fish gets the same nested
// completion via the same binary entry point. Without this, `complete -c hasp
// -n '__fish_use_subcommand'` only ever fires at depth 1.
func TestCompletionCzalFishScriptDescends(t *testing.T) {
	var stdout bytes.Buffer
	if err := completionCommand(context.Background(), []string{"fish"}, &stdout, io.Discard); err != nil {
		t.Fatalf("completion fish: %v", err)
	}
	body := stdout.String()
	if !strings.Contains(body, "__complete") {
		t.Fatalf("fish completion must delegate nested completion to `hasp __complete`:\n%s", body)
	}
}

// TestCompletionCzalPowershellScriptDescends — same contract for powershell.
func TestCompletionCzalPowershellScriptDescends(t *testing.T) {
	var stdout bytes.Buffer
	if err := completionCommand(context.Background(), []string{"powershell"}, &stdout, io.Discard); err != nil {
		t.Fatalf("completion powershell: %v", err)
	}
	body := stdout.String()
	if !strings.Contains(body, "__complete") {
		t.Fatalf("powershell completion must delegate nested completion to `hasp __complete`:\n%s", body)
	}
}

// TestCompletionCzalHiddenCompleteSubcommandRoutes verifies that
// `hasp __complete <args...>` is wired into the top-level dispatcher and emits
// the same candidates the in-process Complete() function returns. The shell
// scripts depend on this entry point, so it must keep working.
func TestCompletionCzalHiddenCompleteSubcommandRoutes(t *testing.T) {
	lockAppSeams(t)

	t.Run("root", func(t *testing.T) {
		var stdout bytes.Buffer
		if err := Run(context.Background(), []string{"__complete"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
			t.Fatalf("Run __complete: %v", err)
		}
		body := stdout.String()
		// Visible root commands must be present.
		for _, name := range []string{"secret", "agent", "run"} {
			if !strings.Contains(body, name) {
				t.Errorf("`hasp __complete` missing root command %q in:\n%s", name, body)
			}
		}
		// Hidden commands must not leak.
		if strings.Contains(body, "redact") {
			t.Errorf("`hasp __complete` leaked hidden command redact:\n%s", body)
		}
	})

	t.Run("nested", func(t *testing.T) {
		var stdout bytes.Buffer
		if err := Run(context.Background(), []string{"__complete", "secret"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
			t.Fatalf("Run __complete secret: %v", err)
		}
		body := stdout.String()
		for _, sub := range []string{"add", "list", "expose"} {
			if !strings.Contains(body, sub) {
				t.Errorf("`hasp __complete secret` missing %q in:\n%s", sub, body)
			}
		}
	})

	t.Run("flags", func(t *testing.T) {
		var stdout bytes.Buffer
		if err := Run(context.Background(), []string{"__complete", "run", "--"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
			t.Fatalf("Run __complete run --: %v", err)
		}
		body := stdout.String()
		if !strings.Contains(body, "--explain") {
			t.Errorf("`hasp __complete run --` missing --explain in:\n%s", body)
		}
	})
}

// TestCompletionCzalHiddenCompleteIsHidden confirms the helper command does
// not appear in `hasp` root listings (it's an internal implementation detail
// for the shell scripts).
func TestCompletionCzalHiddenCompleteIsHidden(t *testing.T) {
	for _, spec := range rootCommandInventory() {
		if spec.name == "__complete" {
			if !spec.hidden {
				t.Fatalf("__complete must be hidden:true so it never appears in user-facing help")
			}
			return
		}
	}
	t.Fatal("__complete subcommand not registered in rootCommandInventory")
}
