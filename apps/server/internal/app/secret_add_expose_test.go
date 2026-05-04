package app

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withinTempRepoForSecretAdd builds a throwaway git repo (just an empty
// `.git` dir is enough for pathLooksLikeGitRepo) and returns its path so
// the caller can pass `--project-root <root>` to drive the in-repo branch.
func withinTempRepoForSecretAdd(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatalf("seed .git: %v", err)
	}
	return dir
}

// TestSecretAddNonInteractiveRequiresExposeChoice locks the security
// fix from the punch list: in a repo, `hasp secret add` used to silently
// auto-bind the new value to that repo. With no tty attached (the script
// case), that's a meaningful mutation the operator never asked for.
//
// Now non-interactive `secret add` inside a repo refuses to auto-bind
// unless the operator picks one of:
//   --vault-only          (don't bind)
//   --expose=never        (don't bind, explicit)
//   --expose=always       (bind, explicit)
//
// Bare `secret add NAME` from a non-tty stdin should error and surface
// the available flags so the operator can pick one.
func TestSecretAddNonInteractiveRequiresExposeChoice(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)
	root := withinTempRepoForSecretAdd(t)

	err := secretAddCommand(ctx, []string{"--project-root", root, "--from-stdin", "TOKEN"}, bytes.NewBufferString("v"), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected non-interactive secret add inside repo to require --expose choice")
	}
	msg := err.Error()
	for _, want := range []string{"--vault-only", "--expose"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should mention %q so the operator knows the flags, got %q", want, msg)
		}
	}
}

// TestSecretAddVaultOnlySkipsBindNonInteractive confirms the existing
// `--vault-only` escape still works once the new gate is in place.
func TestSecretAddVaultOnlySkipsBindNonInteractive(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)
	root := withinTempRepoForSecretAdd(t)

	if err := secretAddCommand(ctx, []string{"--project-root", root, "--from-stdin", "--vault-only", "TOKEN"}, bytes.NewBufferString("v"), io.Discard, io.Discard); err != nil {
		t.Fatalf("--vault-only should still succeed non-interactively: %v", err)
	}
}

// TestSecretAddExposeAlwaysBindsNonInteractive proves `--expose=always`
// is the explicit opt-in for the script path.
func TestSecretAddExposeAlwaysBindsNonInteractive(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)
	root := withinTempRepoForSecretAdd(t)

	if err := secretAddCommand(ctx, []string{"--project-root", root, "--from-stdin", "--expose=always", "TOKEN"}, bytes.NewBufferString("v"), io.Discard, io.Discard); err != nil {
		t.Fatalf("--expose=always should succeed non-interactively: %v", err)
	}
}

// TestSecretAddExposeNeverSkipsBindNonInteractive proves `--expose=never`
// is the explicit no-bind path that doesn't need `--vault-only`.
func TestSecretAddExposeNeverSkipsBindNonInteractive(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)
	root := withinTempRepoForSecretAdd(t)

	if err := secretAddCommand(ctx, []string{"--project-root", root, "--from-stdin", "--expose=never", "TOKEN"}, bytes.NewBufferString("v"), io.Discard, io.Discard); err != nil {
		t.Fatalf("--expose=never should succeed non-interactively: %v", err)
	}
}

// TestSecretAddExposeRejectsUnknownValue guards the enum so a typo
// (--expose=automatic) doesn't fall through to the silent-auto-bind path.
func TestSecretAddExposeRejectsUnknownValue(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)

	err := secretAddCommand(ctx, []string{"--from-stdin", "--expose=maybe", "TOKEN"}, bytes.NewBufferString("v"), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error for unknown --expose value")
	}
	if !strings.Contains(err.Error(), "expose") {
		t.Errorf("error should mention --expose, got %v", err)
	}
}

// TestSecretAddExposeAndVaultOnlyConflict prevents an operator from
// passing both `--vault-only` and `--expose=always` (contradictory).
func TestSecretAddExposeAndVaultOnlyConflict(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)

	err := secretAddCommand(ctx, []string{"--from-stdin", "--vault-only", "--expose=always", "TOKEN"}, bytes.NewBufferString("v"), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected conflict error for --vault-only + --expose=always")
	}
}
