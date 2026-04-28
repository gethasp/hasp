package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// hasp-tx8p: split `secret get` into three intent-specific verbs.
//   - secret show   → metadata only (the "is it there, when, what kind?" path)
//   - secret reveal → value to stdout (must be opt-in per existing policy)
//   - secret copy   → clipboard (also opt-in)
//
// `get` and `retrieve` stay as silent aliases for one release. The new verbs
// route through the same underlying implementation; this suite locks the
// dispatch and the visible-output contracts.

func TestSecretShowEmitsMetadataOnly(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "show", "API_TOKEN"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("secret show: %v", err)
	}
	if !strings.Contains(stdout.String(), "API_TOKEN") {
		t.Fatalf("expected metadata to mention name, got %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "abc123") {
		t.Fatalf("secret show must NOT print the value, got %q", stdout.String())
	}
}

func TestSecretRevealPrintsValue(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "reveal", "API_TOKEN"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("secret reveal: %v", err)
	}
	if !strings.Contains(stdout.String(), "abc123") {
		t.Fatalf("expected revealed value, got %q", stdout.String())
	}
}

func TestSecretCopyInvokesClipboard(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	origClipboard := secretClipboardFn
	defer func() { secretClipboardFn = origClipboard }()
	var captured []byte
	secretClipboardFn = func(value []byte) error {
		captured = append([]byte(nil), value...)
		return nil
	}

	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "copy", "API_TOKEN"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("secret copy: %v", err)
	}
	if string(captured) != "abc123" {
		t.Fatalf("clipboard captured %q, want %q", captured, "abc123")
	}
	// Stdout must NOT contain the plaintext when only copied.
	if strings.Contains(stdout.String(), "abc123") {
		t.Fatalf("secret copy must not print the value to stdout, got %q", stdout.String())
	}
}

func TestSecretGetStillWorksAsAlias(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "get", "API_TOKEN", "--reveal"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("secret get alias: %v", err)
	}
	if !strings.Contains(stdout.String(), "abc123") {
		t.Fatalf("expected get alias to still reveal, got %q", stdout.String())
	}
}

func TestSecretShowRejectsRevealFlag(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
	err := Run(context.Background(), []string{"secret", "show", "API_TOKEN", "--reveal"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("secret show must reject --reveal (use secret reveal instead)")
	}
}
