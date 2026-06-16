package app

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withinTempRepoForSecretAdd builds a throwaway git repo and returns its path
// so the caller can pass `--project-root <root>` to drive the in-repo branch.
func withinTempRepoForSecretAdd(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if out, err := initTestGitRepo(dir); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
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
//
//	--vault-only          (don't bind)
//	--expose=never        (don't bind, explicit)
//	--expose=always       (bind, explicit)
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

func TestSecretAddExposeAlwaysCreatesMissingManifestItem(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)
	root := withinTempRepoForSecretAdd(t)
	manifest := `{"version":"v1","references":[{"alias":"gum_oauth_client_secret","item":"GUM_OAUTH_CLIENT_SECRET"}]}`
	if err := os.WriteFile(filepath.Join(root, ".hasp.manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	var out bytes.Buffer
	err := secretAddCommand(ctx, []string{"--project-root", root, "--from-stdin", "--expose=always", "GUM_OAUTH_CLIENT_SECRET"}, bytes.NewBufferString("secret-value\n"), &out, io.Discard)
	if err != nil {
		t.Fatalf("secret add should create missing manifest item: %v", err)
	}
	if !strings.Contains(out.String(), "gum_oauth_client_secret") {
		t.Fatalf("expected manifest alias in output, got %q", out.String())
	}

	var status bytes.Buffer
	if err := projectStatusCommand(ctx, []string{"--json", "--project-root", root}, &status); err != nil {
		t.Fatalf("project status: %v", err)
	}
	for _, want := range []string{"gum_oauth_client_secret", "GUM_OAUTH_CLIENT_SECRET"} {
		if !strings.Contains(status.String(), want) {
			t.Fatalf("project status missing %q: %s", want, status.String())
		}
	}
}

func TestSecretAddExposeAlwaysExplainsUnrelatedMissingManifestItem(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)
	root := withinTempRepoForSecretAdd(t)
	manifest := `{"version":"v1","references":[{"alias":"gum_oauth_client_secret","item":"GUM_OAUTH_CLIENT_SECRET"}]}`
	if err := os.WriteFile(filepath.Join(root, ".hasp.manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	err := secretAddCommand(ctx, []string{"--project-root", root, "--from-stdin", "--expose=always", "OTHER_SECRET"}, bytes.NewBufferString("secret-value\n"), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected unrelated missing manifest item to block auto-expose")
	}
	msg := err.Error()
	for _, want := range []string{"gum_oauth_client_secret", "GUM_OAUTH_CLIENT_SECRET", "hasp secret add --vault-only GUM_OAUTH_CLIENT_SECRET", ".hasp.manifest.json"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("missing %q in error %q", want, msg)
		}
	}
	if strings.TrimSpace(msg) == "item not found" {
		t.Fatalf("expected contextual error, got %q", msg)
	}

	var getOut bytes.Buffer
	if err := secretGetCommand(ctx, []string{"OTHER_SECRET"}, bytes.NewBuffer(nil), &getOut, io.Discard); err == nil {
		t.Fatalf("OTHER_SECRET should not be saved after preflight failure: %s", getOut.String())
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
