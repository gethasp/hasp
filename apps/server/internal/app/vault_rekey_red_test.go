package app

// RED tests for hasp-9922 — `hasp vault rekey` rotates the master password.
// Contract pinned at the CLI surface:
//
//   - Reads the current password from HASP_MASTER_PASSWORD (same convention
//     as `vault rekdf`) and the new password from HASP_NEW_MASTER_PASSWORD.
//   - After rekey, the OLD password no longer unlocks (`hasp version`
//     fails when HASP_MASTER_PASSWORD still references it).
//   - After rekey, the NEW password unlocks normally.
//   - --json emits a parseable payload describing the rotation.
//   - The unknown-positional and missing-new-password paths fail closed.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestVaultRekeyCommandRotatesMasterPassword(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "old-password")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Confirm baseline: old password unlocks.
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}

	t.Setenv("HASP_NEW_MASTER_PASSWORD", "new-password")
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"vault", "rekey"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("vault rekey: %v", err)
	}
	t.Setenv("HASP_NEW_MASTER_PASSWORD", "")

	// Old password must NO LONGER unlock — try a vault-touching command that
	// requires HASP_MASTER_PASSWORD.
	if err := Run(context.Background(), []string{"set", "--name", "POST_REKEY", "--value", "x"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected old password to fail after rekey")
	}

	// New password must unlock.
	t.Setenv("HASP_MASTER_PASSWORD", "new-password")
	if err := Run(context.Background(), []string{"set", "--name", "POST_REKEY", "--value", "x"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set with new password: %v", err)
	}

	if !strings.Contains(stdout.String(), "rekey") && !strings.Contains(stdout.String(), "rotated") {
		t.Fatalf("expected stdout to describe the rotation, got: %q", stdout.String())
	}
}

func TestVaultRekeyCommandJSONReportsState(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "old-password")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	t.Setenv("HASP_NEW_MASTER_PASSWORD", "new-password")
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"vault", "rekey", "--json"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("vault rekey --json: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode json: %v: %q", err, stdout.String())
	}
	if state, _ := payload["vault_state"].(string); state != "rekey_complete" {
		t.Fatalf("vault_state = %v, want rekey_complete", payload["vault_state"])
	}
	// Defense in depth: the JSON payload must NEVER carry password values.
	if strings.Contains(stdout.String(), "old-password") || strings.Contains(stdout.String(), "new-password") {
		t.Fatalf("rekey JSON leaked a password: %q", stdout.String())
	}
}

func TestVaultRekeyRejectsMissingNewPassword(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "old-password")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Setenv("HASP_NEW_MASTER_PASSWORD", "")

	if err := Run(context.Background(), []string{"vault", "rekey"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected error when HASP_NEW_MASTER_PASSWORD is empty")
	}
}

func TestVaultRekeyRejectsUnknownArg(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "old-password")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Setenv("HASP_NEW_MASTER_PASSWORD", "new-password")
	if err := Run(context.Background(), []string{"vault", "rekey", "extra-positional"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected error for extra positional arg")
	}
}

func TestVaultRekeyHelpMentionsRekey(t *testing.T) {
	lockAppSeams(t)
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"help", "vault"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("help vault: %v", err)
	}
	if !strings.Contains(out.String(), "rekey") {
		t.Fatalf("vault help should list rekey subcommand:\n%s", out.String())
	}
}
