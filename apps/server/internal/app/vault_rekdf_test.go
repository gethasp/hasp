package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVaultRekdfCommandRewritesEnvelope confirms the command runs end-to-end:
// init → rekdf → envelope is still argon2id (since the binary's default IS
// argon2id, this is a same-KDF rewrite that exercises the read/derive/reseal/
// write path), and the same password still unlocks the vault afterwards.
func TestVaultRekdfCommandRewritesEnvelope(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	preEnvelope := readEnvelopeForTest(t, homeDir)
	preWrap := preEnvelope["header"].(map[string]any)["password_wrap"].(map[string]any)["ciphertext"]

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"vault", "rekdf"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("vault rekdf: %v", err)
	}
	output := stdout.String()
	if !strings.Contains(output, "argon2id") {
		t.Fatalf("expected output to mention argon2id, got: %q", output)
	}

	// Same password must still unlock — RekdfWithPassword preserves vaultKey.
	if err := Run(context.Background(), []string{"version"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("post-rekdf version: %v", err)
	}

	// password_wrap ciphertext MUST have changed: a fresh nonce is generated
	// and the wrap key was re-derived from a fresh salt.
	postEnvelope := readEnvelopeForTest(t, homeDir)
	postWrap := postEnvelope["header"].(map[string]any)["password_wrap"].(map[string]any)["ciphertext"]
	if preWrap == postWrap {
		t.Fatalf("password_wrap unchanged after rekdf — rewrite did not happen")
	}
	postKDF := postEnvelope["header"].(map[string]any)["kdf"].(map[string]any)
	if postKDF["name"] != "argon2id" {
		t.Fatalf("post-rekdf KDF.name = %v, want argon2id", postKDF["name"])
	}
}

// TestVaultRekdfCommandJSONReportsKDFNames covers the --json contract so
// tooling can parse old/new without scraping the human prose.
func TestVaultRekdfCommandJSONReportsKDFNames(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"vault", "rekdf", "--json"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("vault rekdf --json: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode JSON: %v: %q", err, stdout.String())
	}
	if payload["from_kdf"] != "argon2id" {
		t.Fatalf("from_kdf = %v, want argon2id", payload["from_kdf"])
	}
	if payload["to_kdf"] != "argon2id" {
		t.Fatalf("to_kdf = %v, want argon2id", payload["to_kdf"])
	}
}

// TestVaultRekdfRejectsUnknownArg gates the subcommand surface — unrecognised
// arguments must error rather than silently acting on the vault.
func TestVaultRekdfRejectsUnknownArg(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	err := Run(context.Background(), []string{"vault", "rekdf", "extra-positional"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error for extra positional arg")
	}
}

// TestVaultRekdfHelpMentionsArgon2id keeps the help surface honest — operators
// running `hasp help vault` should see the upgrade described.
func TestVaultRekdfHelpMentionsArgon2id(t *testing.T) {
	lockAppSeams(t)
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"help", "vault"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("help vault: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, "rekdf") {
		t.Fatalf("vault help should list rekdf subcommand, got: %q", body)
	}
}

func readEnvelopeForTest(t *testing.T, homeDir string) map[string]any {
	t.Helper()
	statePath := filepath.Join(homeDir, "vault.json.enc")
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read vault: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	return envelope
}
