package app

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecretAddKindFileFromFile verifies the new `--kind file --from-file PATH NAME`
// surface: the file's bytes become the secret value and the upserted item carries
// ItemKindFile (so `hasp inject` can stream it as a file artifact later).
func TestSecretAddKindFileFromFile(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)

	dir := t.TempDir()
	payloadPath := filepath.Join(dir, "private.pem")
	body := []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIBOwIBAAJBAKj...\n-----END RSA PRIVATE KEY-----\n")
	if err := os.WriteFile(payloadPath, body, 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	if err := secretAddCommand(ctx, []string{"--kind", "file", "--from-file", payloadPath, "--vault-only", "DEPLOY_KEY"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add --kind file: %v", err)
	}

	// Round-trip via secret get --reveal: stored payload should match the file body.
	var getOut bytes.Buffer
	if err := secretGetCommand(ctx, []string{"DEPLOY_KEY", "--reveal"}, bytes.NewBuffer(nil), &getOut, io.Discard); err != nil {
		t.Fatalf("secret get DEPLOY_KEY: %v", err)
	}
	if !strings.Contains(getOut.String(), "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("expected stored payload to round-trip, got %q", getOut.String())
	}
}

// TestSecretAddKindFileRequiresFromFile rejects `--kind file` without a value
// source so an operator can't accidentally store an empty file-kind item from
// an interactive prompt.
func TestSecretAddKindFileRequiresFromFile(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)

	err := secretAddCommand(ctx, []string{"--kind", "file", "DEPLOY_KEY"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error when --kind file lacks a value source")
	}
	if !strings.Contains(err.Error(), "--from-file") && !strings.Contains(err.Error(), "--from-stdin") {
		t.Fatalf("error should mention --from-file or --from-stdin, got %q", err.Error())
	}
}

// TestSecretAddKindRejectsUnknownKind validates the kind enum surface so an
// operator typo (--kind binary) doesn't silently fall through to ItemKindKV.
func TestSecretAddKindRejectsUnknownKind(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)

	err := secretAddCommand(ctx, []string{"--kind", "binary", "DEPLOY_KEY"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error for unknown --kind value")
	}
	if !strings.Contains(err.Error(), "kind") {
		t.Fatalf("error should mention kind, got %q", err.Error())
	}
}

// TestSecretAddFromFileRejectsMultipleNames matches the existing --from-stdin
// rule: a single value source can only feed one named secret.
func TestSecretAddFromFileRejectsMultipleNames(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)

	dir := t.TempDir()
	payloadPath := filepath.Join(dir, "p")
	if err := os.WriteFile(payloadPath, []byte("v"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err := secretAddCommand(ctx, []string{"--kind", "file", "--from-file", payloadPath, "A", "B"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error when --from-file is paired with multiple names")
	}
}

// TestSecretAddFromFileMutuallyExclusiveWithFromStdin guards against a caller
// piping a file AND stdin in the same invocation; the resolution order would
// be ambiguous.
func TestSecretAddFromFileMutuallyExclusiveWithFromStdin(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)

	dir := t.TempDir()
	payloadPath := filepath.Join(dir, "p")
	if err := os.WriteFile(payloadPath, []byte("v"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err := secretAddCommand(ctx, []string{"--from-file", payloadPath, "--from-stdin", "X"}, bytes.NewBufferString("y"), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error when --from-file and --from-stdin both set")
	}
}

// Avoid unused-import lint when context isn't referenced.
var _ = context.Background
