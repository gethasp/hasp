package app

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
)

// bootstrap initialises a vault, stores api_token=abc123, and binds the
// project root with secret_01=api_token. Returns the project root.
func bootstrapVaultForOverwriteTests(t *testing.T) string {
	t.Helper()
	homeDir := t.TempDir()
	projectRoot := t.TempDir()

	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	origEnsureSession := ensureSessionAppFn
	t.Cleanup(func() { ensureSessionAppFn = origEnsureSession })
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "test-session"}, nil
	}

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set api_token: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "secret_01=api_token"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run project bind: %v", err)
	}

	return projectRoot
}

// writeEnvArgs returns the standard full-grant args for write-env pointed at
// outputPath with the given extra flags appended.
func writeEnvArgs(projectRoot, outputPath string, extra ...string) []string {
	base := []string{
		"--project-root", projectRoot,
		"--output", outputPath,
		"--env", "API_TOKEN=secret_01",
		"--grant-project", "window",
		"--grant-secret", "session",
		"--grant-convenience", "window",
		"--grant-window", "15m",
	}
	return append(base, extra...)
}

// TestWriteEnvRefusesOverwriteWithoutForce: existing file, no --force, no
// --append → error, file bytes unchanged.
func TestWriteEnvRefusesOverwriteWithoutForce(t *testing.T) {
	lockAppSeams(t)
	projectRoot := bootstrapVaultForOverwriteTests(t)

	outputPath := filepath.Join(t.TempDir(), "existing.env")
	original := []byte("DO_NOT_CLOBBER=1\n")
	if err := os.WriteFile(outputPath, original, 0o600); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	err := writeEnvCommand(context.Background(),
		writeEnvArgs(projectRoot, outputPath), // no --force, no --append
		io.Discard, io.Discard, &fakeStarter{})
	if err == nil {
		t.Fatal("expected an error refusing to overwrite existing file")
	}
	msg := err.Error()
	if !strings.Contains(msg, "--force") && !strings.Contains(msg, "overwrite") {
		t.Fatalf("error message should mention --force or overwrite, got: %q", msg)
	}

	got, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatalf("read file after refused overwrite: %v", readErr)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("file was modified despite overwrite refusal: got %q, want %q", got, original)
	}
}

// TestWriteEnvOverwritesWithForce: existing file + --force → success, new
// content replaces old content.
func TestWriteEnvOverwritesWithForce(t *testing.T) {
	lockAppSeams(t)
	projectRoot := bootstrapVaultForOverwriteTests(t)

	outputPath := filepath.Join(t.TempDir(), "existing.env")
	if err := os.WriteFile(outputPath, []byte("OLD=content\n"), 0o600); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	err := writeEnvCommand(context.Background(),
		writeEnvArgs(projectRoot, outputPath, "--force"),
		io.Discard, io.Discard, &fakeStarter{})
	if err != nil {
		t.Fatalf("expected no error with --force, got: %v", err)
	}

	got, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatalf("read file after --force overwrite: %v", readErr)
	}
	if strings.Contains(string(got), "OLD=content") {
		t.Fatalf("old content should be gone after --force overwrite, got: %q", string(got))
	}
	if !strings.Contains(string(got), "API_TOKEN=abc123") {
		t.Fatalf("new env line missing after --force overwrite, got: %q", string(got))
	}
}

// TestWriteEnvForceAndAppendIsUsageError: --force + --append is a usage error.
func TestWriteEnvForceAndAppendIsUsageError(t *testing.T) {
	lockAppSeams(t)
	projectRoot := bootstrapVaultForOverwriteTests(t)

	outputPath := filepath.Join(t.TempDir(), "any.env")

	err := writeEnvCommand(context.Background(),
		writeEnvArgs(projectRoot, outputPath, "--force", "--append"),
		io.Discard, io.Discard, &fakeStarter{})
	if err == nil {
		t.Fatal("expected error when both --force and --append are set")
	}
}

// TestWriteEnvAppendAddsDelimitedBlockToExistingFile: existing file without a
// hasp block → append adds the block after existing content.
func TestWriteEnvAppendAddsDelimitedBlockToExistingFile(t *testing.T) {
	lockAppSeams(t)
	projectRoot := bootstrapVaultForOverwriteTests(t)

	outputPath := filepath.Join(t.TempDir(), "append.env")
	if err := os.WriteFile(outputPath, []byte("EXISTING=1\n"), 0o600); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	err := writeEnvCommand(context.Background(),
		writeEnvArgs(projectRoot, outputPath, "--append"),
		io.Discard, io.Discard, &fakeStarter{})
	if err != nil {
		t.Fatalf("write-env --append: %v", err)
	}

	got, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatalf("read file: %v", readErr)
	}
	content := string(got)

	if !strings.Contains(content, "EXISTING=1") {
		t.Fatalf("EXISTING=1 not preserved: %q", content)
	}
	if !strings.Contains(content, "# --- hasp begin ---") {
		t.Fatalf("hasp begin marker missing: %q", content)
	}
	if !strings.Contains(content, "# --- hasp end ---") {
		t.Fatalf("hasp end marker missing: %q", content)
	}
	if !strings.Contains(content, "API_TOKEN=abc123") {
		t.Fatalf("env value missing: %q", content)
	}

	// Order: EXISTING=1 must come before begin, env line must be between markers.
	idxExisting := strings.Index(content, "EXISTING=1")
	idxBegin := strings.Index(content, "# --- hasp begin ---")
	idxEnv := strings.Index(content, "API_TOKEN=abc123")
	idxEnd := strings.Index(content, "# --- hasp end ---")

	if idxExisting >= idxBegin || idxBegin >= idxEnv || idxEnv >= idxEnd {
		t.Fatalf("content not in expected order (existing<begin<env<end): %q", content)
	}
}

// TestWriteEnvAppendIsIdempotent: calling --append twice produces byte-identical
// output on the second run.
func TestWriteEnvAppendIsIdempotent(t *testing.T) {
	lockAppSeams(t)
	projectRoot := bootstrapVaultForOverwriteTests(t)

	outputPath := filepath.Join(t.TempDir(), "idempotent.env")
	if err := os.WriteFile(outputPath, []byte("EXISTING=1\n"), 0o600); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	args := writeEnvArgs(projectRoot, outputPath, "--append")

	if err := writeEnvCommand(context.Background(), args, io.Discard, io.Discard, &fakeStarter{}); err != nil {
		t.Fatalf("first --append: %v", err)
	}
	first, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read after first --append: %v", err)
	}

	if err := writeEnvCommand(context.Background(), args, io.Discard, io.Discard, &fakeStarter{}); err != nil {
		t.Fatalf("second --append: %v", err)
	}
	second, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read after second --append: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Fatalf("--append is not idempotent:\nfirst:  %q\nsecond: %q", first, second)
	}
}

// TestWriteEnvAppendOnNonexistentFileCreatesBlock: --append on a path that
// does not exist creates the file with a hasp block and 0600 perms.
func TestWriteEnvAppendOnNonexistentFileCreatesBlock(t *testing.T) {
	lockAppSeams(t)
	projectRoot := bootstrapVaultForOverwriteTests(t)

	outputPath := filepath.Join(t.TempDir(), "new.env")

	err := writeEnvCommand(context.Background(),
		writeEnvArgs(projectRoot, outputPath, "--append"),
		io.Discard, io.Discard, &fakeStarter{})
	if err != nil {
		t.Fatalf("write-env --append on non-existent file: %v", err)
	}

	info, statErr := os.Stat(outputPath)
	if statErr != nil {
		t.Fatalf("file not created: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected 0600 perms, got %04o", perm)
	}

	got, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatalf("read created file: %v", readErr)
	}
	content := string(got)
	if !strings.Contains(content, "# --- hasp begin ---") {
		t.Fatalf("hasp begin marker missing: %q", content)
	}
	if !strings.Contains(content, "# --- hasp end ---") {
		t.Fatalf("hasp end marker missing: %q", content)
	}
	if !strings.Contains(content, "API_TOKEN=abc123") {
		t.Fatalf("env value missing: %q", content)
	}
}

// TestWriteEnvAppendReplacesBlockBodyPreservingSurroundingContent: when the
// file already contains a hasp block, --append replaces the block body while
// preserving content before and after.
func TestWriteEnvAppendReplacesBlockBodyPreservingSurroundingContent(t *testing.T) {
	lockAppSeams(t)
	projectRoot := bootstrapVaultForOverwriteTests(t)

	outputPath := filepath.Join(t.TempDir(), "replace.env")
	initial := "BEFORE=before\n# --- hasp begin ---\nOLD_VAR=oldvalue\n# --- hasp end ---\nAFTER=after\n"
	if err := os.WriteFile(outputPath, []byte(initial), 0o600); err != nil {
		t.Fatalf("write initial file: %v", err)
	}

	err := writeEnvCommand(context.Background(),
		writeEnvArgs(projectRoot, outputPath, "--append"),
		io.Discard, io.Discard, &fakeStarter{})
	if err != nil {
		t.Fatalf("write-env --append replace block: %v", err)
	}

	got, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatalf("read file: %v", readErr)
	}
	content := string(got)

	if !strings.Contains(content, "BEFORE=before") {
		t.Fatalf("BEFORE=before not preserved: %q", content)
	}
	if !strings.Contains(content, "AFTER=after") {
		t.Fatalf("AFTER=after not preserved: %q", content)
	}
	if strings.Contains(content, "OLD_VAR=oldvalue") {
		t.Fatalf("OLD_VAR=oldvalue should be replaced, still present: %q", content)
	}
	if !strings.Contains(content, "API_TOKEN=abc123") {
		t.Fatalf("new env value missing: %q", content)
	}

	// Exactly one begin/end pair.
	if strings.Count(content, "# --- hasp begin ---") != 1 {
		t.Fatalf("expected exactly one hasp begin marker: %q", content)
	}
	if strings.Count(content, "# --- hasp end ---") != 1 {
		t.Fatalf("expected exactly one hasp end marker: %q", content)
	}

	// AFTER=after must appear after the end marker.
	idxEnd := strings.Index(content, "# --- hasp end ---")
	idxAfter := strings.Index(content, "AFTER=after")
	if idxEnd >= idxAfter {
		t.Fatalf("AFTER=after should appear after hasp end marker: %q", content)
	}
}

// TestWriteEnvAppendRefusesAmbiguousMultipleBlocks: file with two hasp
// begin/end pairs → --append returns an error, file bytes unchanged.
func TestWriteEnvAppendRefusesAmbiguousMultipleBlocks(t *testing.T) {
	lockAppSeams(t)
	projectRoot := bootstrapVaultForOverwriteTests(t)

	outputPath := filepath.Join(t.TempDir(), "ambiguous.env")
	ambiguous := "# --- hasp begin ---\nA=1\n# --- hasp end ---\n# --- hasp begin ---\nB=2\n# --- hasp end ---\n"
	if err := os.WriteFile(outputPath, []byte(ambiguous), 0o600); err != nil {
		t.Fatalf("write ambiguous file: %v", err)
	}

	err := writeEnvCommand(context.Background(),
		writeEnvArgs(projectRoot, outputPath, "--append"),
		io.Discard, io.Discard, &fakeStarter{})
	if err == nil {
		t.Fatal("expected error for ambiguous multiple hasp blocks")
	}

	got, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatalf("read file after refused ambiguous append: %v", readErr)
	}
	if string(got) != ambiguous {
		t.Fatalf("file was modified despite ambiguous-block refusal:\ngot:  %q\nwant: %q", string(got), ambiguous)
	}
}
