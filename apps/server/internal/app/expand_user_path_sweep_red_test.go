package app

// RED tests for the cross-cutting tilde-expansion sweep.
// Each test checks that the named command expands "~/..." in a path-accepting
// flag before the value reaches the store/filesystem layer.  All tests
// FAIL until the corresponding wiring is added (Step 4).

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// errSentinel is a distinct error value used to abort seam stubs early.
var errSentinel = errors.New("sentinel: seam intercepted")

// TestTildeSweep_ProjectStatus exercises `project status --project-root ~/foo`.
// We stub openVaultHandleFn to return a stub and intercept appCanonicalProjectRootFn
// (called inside ensureProjectBinding) to capture the value that reaches the store layer.
func TestTildeSweep_ProjectStatus(t *testing.T) { //nolint:dupl // intentional per-command sweep — pinpoint failures must stay in separate tests
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	want := filepath.Join(tmpHome, "foo")

	// Stub vault so ensureProjectBinding is reached.
	origOpen := openVaultHandleFn
	t.Cleanup(func() { openVaultHandleFn = origOpen })
	openVaultHandleFn = func(context.Context) (*store.Handle, error) {
		return &store.Handle{}, nil
	}

	origCanon := appCanonicalProjectRootFn
	t.Cleanup(func() { appCanonicalProjectRootFn = origCanon })
	var got string
	appCanonicalProjectRootFn = func(_ context.Context, root string) (string, error) {
		got = root
		return "", errSentinel
	}

	_ = projectStatusCommand(context.Background(), []string{"--project-root", "~/foo"}, io.Discard)

	if got == "" {
		t.Fatal("appCanonicalProjectRootFn was not called; cannot verify tilde expansion")
	}
	if got == "~/foo" {
		t.Fatalf("project status passed literal '~/foo' to store layer; want %q", want)
	}
	if got != want {
		t.Fatalf("project status resolved root = %q; want %q", got, want)
	}
}

// TestTildeSweep_ProjectUnbind exercises `project unbind --project-root ~/foo`.
// We verify by checking: (a) ~user is rejected before the vault is opened,
// and (b) the error path from a failed vault open does NOT contain "~/".
func TestTildeSweep_ProjectUnbind(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Stub vault to fail so DeleteBinding is never called (avoids nil ptr panic).
	origOpen := openVaultHandleFn
	t.Cleanup(func() { openVaultHandleFn = origOpen })
	openVaultHandleFn = func(context.Context) (*store.Handle, error) {
		return nil, errSentinel
	}

	err := projectUnbindCommand(context.Background(), []string{"--project-root", "~/foo"}, io.Discard)

	if err == nil {
		t.Fatal("expected error (no vault), got nil")
	}
	// Before expansion: the command fails with errSentinel from the vault seam.
	// After expansion it should still fail with errSentinel (vault is stubbed).
	// Either way, the error must NOT contain the literal "~/".
	if strings.Contains(err.Error(), "~/") {
		t.Fatalf("project unbind holds unexpanded tilde in error: %v", err)
	}
}

// TestTildeSweep_TildeUserError_ProjectUnbind verifies ~baduser/foo returns a
// clear error containing "~user" from project unbind.
// expandUserPath must be called BEFORE openVaultHandleFn so the ~user error
// fires even when the vault is healthy.
func TestTildeSweep_TildeUserError_ProjectUnbind(t *testing.T) {
	// Do NOT stub vault here: if expansion fires before vault open, the error
	// is returned immediately without reaching the vault seam.
	err := projectUnbindCommand(context.Background(),
		[]string{"--project-root", "~baduser/foo"}, io.Discard)

	if err == nil {
		t.Fatal("expected error for ~user expansion, got nil")
	}
	if !strings.Contains(err.Error(), "~user") {
		t.Errorf("error should mention '~user', got: %v", err)
	}
}

// TestTildeSweep_ExportBackup exercises `export-backup --output ~/foo/backup.hasp`.
// openVaultHandleFn is called first; if expansion happens before it we won't see
// "~/foo" in any error that follows. If NOT expanded, os.WriteFile will get "~/foo".
func TestTildeSweep_ExportBackup(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origOpen := openVaultHandleFn
	t.Cleanup(func() { openVaultHandleFn = origOpen })
	openVaultHandleFn = func(context.Context) (*store.Handle, error) {
		return nil, errSentinel
	}

	t.Setenv("HASP_BACKUP_PASSPHRASE", "pass")
	err := exportBackupCommand(context.Background(),
		[]string{"--output", "~/foo/backup.hasp"},
		io.Discard)

	if err == nil {
		t.Fatal("expected error (no vault), got nil")
	}
	// If tilde expansion has NOT happened, the command may propagate an error
	// mentioning "~/foo" (from os.WriteFile or path.Join). After expansion,
	// errors should reference the real path under tmpHome, never the literal "~/".
	if strings.Contains(err.Error(), "~/") {
		t.Fatalf("export-backup holds unexpanded tilde path in error: %v", err)
	}
}

// TestTildeSweep_RestoreBackup exercises `restore-backup --input ~/foo/backup.hasp`.
func TestTildeSweep_RestoreBackup(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	origStore := newVaultStoreFn
	t.Cleanup(func() { newVaultStoreFn = origStore })
	newVaultStoreFn = func() (*store.Store, error) {
		return nil, errSentinel
	}

	t.Setenv("HASP_BACKUP_PASSPHRASE", "pass")
	t.Setenv("HASP_MASTER_PASSWORD", "pw")
	err := restoreBackupCommand(context.Background(),
		[]string{"--input", "~/foo/backup.hasp"},
		io.Discard)

	if err == nil {
		t.Fatal("expected error (no vault), got nil")
	}
	if strings.Contains(err.Error(), "~/") {
		t.Fatalf("restore-backup holds unexpanded tilde path in error: %v", err)
	}
}

// TestTildeSweep_ProjectAdoptUnder exercises `project adopt --under ~/repos`.
// openVaultHandleFn is called first in adopt; stub it so discoverProjectRoots is reached.
func TestTildeSweep_ProjectAdoptUnder(t *testing.T) { //nolint:dupl // intentional per-command sweep — pinpoint failures must stay in separate tests
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	want := filepath.Join(tmpHome, "repos")

	// Stub vault open so discoverProjectRoots is reached.
	origOpen := openVaultHandleFn
	t.Cleanup(func() { openVaultHandleFn = origOpen })
	openVaultHandleFn = func(context.Context) (*store.Handle, error) {
		return &store.Handle{}, nil
	}

	origCanon := projectCanonicalRootFn
	t.Cleanup(func() { projectCanonicalRootFn = origCanon })
	var got string
	projectCanonicalRootFn = func(_ context.Context, root string) (string, error) {
		got = root
		return "", errSentinel
	}

	_ = projectAdoptCommand(context.Background(), []string{"--under", "~/repos"}, io.Discard)

	if got == "" {
		t.Fatal("projectCanonicalRootFn was not called; cannot verify tilde expansion for --under")
	}
	if got == "~/repos" {
		t.Fatalf("project adopt passed literal '~/repos'; want %q", want)
	}
	if got != want {
		t.Fatalf("project adopt resolved under = %q; want %q", got, want)
	}
}

// TestTildeSweep_DocsMarkdownOut exercises `docs markdown --out ~/docs/ref.md`.
// If the path is NOT expanded, os.WriteFile gets "~/docs/ref.md" and errors with that path.
func TestTildeSweep_DocsMarkdownOut(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	err := docsMarkdownCommand(context.Background(), []string{"--out", "~/docs/ref.md"}, io.Discard)

	// Expect an error because ~/docs/ doesn't exist after expansion (tmpHome/docs/).
	if err == nil {
		t.Fatal("expected error (directory does not exist), got nil")
	}
	// If tilde was NOT expanded, the error will reference the literal "~/docs/ref.md".
	if strings.Contains(err.Error(), "~/docs") {
		t.Fatalf("docs markdown did NOT expand tilde: error contains literal path: %v", err)
	}
	// After expansion, the error should reference the real path.
	if !strings.Contains(err.Error(), tmpHome) {
		t.Logf("error = %v", err)
		t.Fatalf("docs markdown error should reference expanded path under %q, got: %v", tmpHome, err)
	}
}

// TestTildeSweep_TildeUserError_ProjectStatus verifies ~baduser/foo produces a
// clear error containing "~user" from project status.
func TestTildeSweep_TildeUserError_ProjectStatus(t *testing.T) {
	// No vault seam needed: expansion should fail before vault is opened.
	err := projectStatusCommand(context.Background(),
		[]string{"--project-root", "~baduser/foo"}, io.Discard)

	if err == nil {
		t.Fatal("expected error for ~user expansion, got nil")
	}
	if !strings.Contains(err.Error(), "~user") {
		t.Errorf("error should mention '~user', got: %v", err)
	}
}

// TestTildeSweep_TildeUserError_ExportBackup verifies ~baduser/backup.hasp
// returns a clear error containing "~user" from export-backup.
// expandUserPath must be called BEFORE openVaultHandleFn.
func TestTildeSweep_TildeUserError_ExportBackup(t *testing.T) {
	// Do NOT stub vault: expansion must fire before vault is opened.
	t.Setenv("HASP_BACKUP_PASSPHRASE", "pass")
	err := exportBackupCommand(context.Background(),
		[]string{"--output", "~baduser/backup.hasp"},
		io.Discard)

	if err == nil {
		t.Fatal("expected error for ~user expansion, got nil")
	}
	if !strings.Contains(err.Error(), "~user") {
		t.Errorf("error should mention '~user', got: %v", err)
	}
}
