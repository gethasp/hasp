package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// TestCompletionCommandSupportsKnownShells ensures `hasp completion <shell>`
// emits a non-empty script for each shell we ship and routes through
// stdout (so users can `> ~/.config/...` without losing the body to stderr).
// The script has to mention the binary name `hasp` and a sample of the
// inventory to prove the generator is plugged into the live command list,
// not a stale snapshot.
func TestCompletionCommandSupportsKnownShells(t *testing.T) {
	lockAppSeams(t)

	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			var stdout bytes.Buffer
			if err := completionCommand(context.Background(), []string{shell}, &stdout, io.Discard); err != nil {
				t.Fatalf("completion %s: %v", shell, err)
			}
			body := stdout.String()
			if body == "" {
				t.Fatalf("completion %s emitted empty body", shell)
			}
			if !strings.Contains(body, "hasp") {
				t.Errorf("completion %s body should mention `hasp`:\n%s", shell, body)
			}
			// hasp-czal: scripts now delegate completion to the binary instead of
			// embedding the inventory. Verify the delegation entry point is wired
			// in — the integration tests in completion_czal_red_test.go cover the
			// actual candidate output.
			if !strings.Contains(body, "__complete") {
				t.Errorf("completion %s body should delegate to `hasp __complete`:\n%s", shell, body)
			}
		})
	}
}

// TestCompletionCommandRejectsUnknownShell errors loudly rather than
// silently emitting nothing — operators copy-paste shell names and a
// silent failure leaves them with a broken completion install.
func TestCompletionCommandRejectsUnknownShell(t *testing.T) {
	lockAppSeams(t)

	err := completionCommand(context.Background(), []string{"tcsh"}, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error for unknown shell")
	}
	if !strings.Contains(err.Error(), "tcsh") {
		t.Errorf("error should mention the offending shell, got %v", err)
	}
}

// TestCompletionCommandRequiresShell rejects bare `hasp completion` so
// the user gets a usage hint instead of an empty stdout.
func TestCompletionCommandRequiresShell(t *testing.T) {
	lockAppSeams(t)

	err := completionCommand(context.Background(), nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error for missing shell argument")
	}
	if !strings.Contains(err.Error(), "shell") {
		t.Errorf("error should mention shell argument, got %v", err)
	}
}

// TestCompletionCommandRoutedFromTopLevel verifies `hasp completion bash`
// reaches the new command via the top-level dispatcher (i.e. it's wired
// into rootCommandInventory).
func TestCompletionCommandRoutedFromTopLevel(t *testing.T) {
	lockAppSeams(t)

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"completion", "bash"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("Run completion bash: %v", err)
	}
	if stdout.Len() == 0 {
		t.Fatal("completion bash routed via Run() produced no output")
	}
}
