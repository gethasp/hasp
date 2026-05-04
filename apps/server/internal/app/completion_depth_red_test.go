package app

// RED-phase tests for hasp-qcis: deep shell completion engine.
//
// These tests reference Complete() and CompletionOptions which do NOT yet
// exist. They will fail to compile until the green phase implements them in
// completion.go (or a new file).
//
// Expected API (green phase must implement):
//
//	type CompletionOptions struct {
//	    IncludeSecretNames bool // opt-in: privacy tradeoff
//	}
//
//	func Complete(args []string, opts CompletionOptions) []string

import (
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

// TestCompletionDepthSecretSubcommands verifies that Complete(["secret"], ...)
// returns the subcommands of `hasp secret` (add, list, get, expose, hide, etc.)
// and does NOT return top-level command names like "run" or "init".
func TestCompletionDepthSecretSubcommands(t *testing.T) {
	t.Setenv(paths.EnvHome, t.TempDir())

	got := Complete([]string{"secret"}, CompletionOptions{})

	wantSubs := []string{"add", "list", "get", "expose", "hide"}
	for _, sub := range wantSubs {
		found := false
		for _, c := range got {
			if c == sub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Complete([\"secret\"]) missing subcommand %q; got: %v", sub, got)
		}
	}

	// Must not bleed top-level names into subcommand context.
	for _, c := range got {
		if c == "run" || c == "init" || c == "agent" {
			t.Errorf("Complete([\"secret\"]) returned top-level command %q; got: %v", c, got)
		}
	}
}

// TestCompletionDepthRunFlags verifies that Complete(["run", "--"], ...)
// returns flag completions for `hasp run` including --explain, --dry-run, and
// --grant-project.
func TestCompletionDepthRunFlags(t *testing.T) {
	t.Setenv(paths.EnvHome, t.TempDir())

	got := Complete([]string{"run", "--"}, CompletionOptions{})

	wantFlags := []string{"--explain", "--dry-run", "--grant-project"}
	for _, flag := range wantFlags {
		found := false
		for _, c := range got {
			if c == flag {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Complete([\"run\", \"--\"]) missing flag %q; got: %v", flag, got)
		}
	}
}

// TestCompletionDepthHiddenCommandsExcluded verifies that hidden commands
// (redact has hidden:true in rootCommandInventory) do NOT appear in root-level
// completions returned by Complete(nil, ...) or Complete([], ...).
func TestCompletionDepthHiddenCommandsExcluded(t *testing.T) {
	t.Setenv(paths.EnvHome, t.TempDir())

	got := Complete([]string{}, CompletionOptions{})

	for _, c := range got {
		if c == "redact" {
			t.Errorf("Complete([]) returned hidden command \"redact\"; it must be omitted; got: %v", got)
		}
	}

	// Sanity: visible top-level commands must still appear.
	wantVisible := []string{"secret", "run", "agent"}
	for _, name := range wantVisible {
		found := false
		for _, c := range got {
			if c == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Complete([]) missing visible command %q; got: %v", name, got)
		}
	}
}

// TestCompletionDepthBashScriptDescendsSubcommands verifies that the bash
// completion script produced by writeBashCompletion (or equivalent) handles
// nested completion — historically by hard-coded subcommand cases, now by
// delegating to the in-binary `hasp __complete` (hasp-czal).
func TestCompletionDepthBashScriptDescendsSubcommands(t *testing.T) {
	t.Setenv(paths.EnvHome, t.TempDir())

	script, err := RenderBashCompletionScript()
	if err != nil {
		t.Fatalf("RenderBashCompletionScript(): %v", err)
	}

	if !strings.Contains(script, "COMP_WORDS") {
		t.Error("bash completion script must reference COMP_WORDS")
	}
	if !strings.Contains(script, "COMP_CWORD") {
		t.Error("bash completion script must reference COMP_CWORD for depth detection")
	}
	// hasp-czal: nested dispatch now lives inside the binary. The script must
	// hand the words off rather than hard-code per-subcommand branches.
	if !strings.Contains(script, "__complete") {
		t.Error("bash completion script must delegate nested completion to `hasp __complete`")
	}
	// Old broken pattern only handled depth 1.
	if strings.Contains(script, `"$COMP_CWORD" -le 1`) && !strings.Contains(script, "__complete") {
		t.Error("bash completion script only handles depth 1; subcommand depth is not implemented")
	}
}

// TestCompletionDepthZshScriptDescendsSubcommands verifies that the zsh
// completion script descends past the root word — either by hand-rolled state
// machine or by delegating to `hasp __complete` (hasp-czal).
func TestCompletionDepthZshScriptDescendsSubcommands(t *testing.T) {
	t.Setenv(paths.EnvHome, t.TempDir())

	script, err := RenderZshCompletionScript()
	if err != nil {
		t.Fatalf("RenderZshCompletionScript(): %v", err)
	}

	if !strings.Contains(script, "compdef") {
		t.Error("zsh completion script must reference compdef")
	}
	if !strings.Contains(script, "__complete") {
		t.Error("zsh completion script must delegate nested completion to `hasp __complete`")
	}
}
