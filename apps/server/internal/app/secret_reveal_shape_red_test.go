package app

// hasp-jx3r: Fix `secret reveal` JSON shape and trailing-newline behaviour.
//
// ISSUE 1 — JSON shape migration:
//   Old shape: {"secret":{...metadata...},"value":"raw"}
//   New shape: {"secret":{...metadata...,"value":"raw"}}
//   Consumers: jq -r .secret.value   (was: jq -r .value)
//
// ISSUE 2 — Trailing newline:
//   Non-TTY stdout → no trailing 0x0a (safe for pbcopy / xclip).
//   TTY stdout     → append one trailing newline (clean shell prompt).
//   --newline      → always append regardless of TTY state.
//   --no-newline   → never append regardless of TTY state.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// --- helpers shared across this file ---

func revealSetup(t *testing.T) {
	t.Helper()
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(),
		[]string{"set", "--name", "API_TOKEN", "--value", "abc123"},
		bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
}

// --- ISSUE 1: JSON shape ---

// TestSecretRevealJSONValueNestedInSecret verifies that --json output nests
// "value" inside "secret", not at the top level.
// Assertion: out["secret"]["value"] == "abc123", out["value"] must not exist.
func TestSecretRevealJSONValueNestedInSecret(t *testing.T) {
	revealSetup(t)
	var out bytes.Buffer
	if err := Run(context.Background(),
		[]string{"secret", "reveal", "--json", "API_TOKEN"},
		bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("secret reveal --json: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("json decode: %v — raw: %q", err, out.String())
	}

	// Top-level "value" must NOT exist.
	if _, ok := decoded["value"]; ok {
		t.Errorf("top-level 'value' key must not exist (migration: nest inside secret); got %v", decoded)
	}
	if _, ok := decoded["value_base64"]; ok {
		t.Errorf("top-level 'value_base64' key must not exist (migration: nest inside secret); got %v", decoded)
	}

	// "secret" must be a sub-object.
	secretRaw, ok := decoded["secret"]
	if !ok {
		t.Fatalf("top-level 'secret' key missing; got keys: %v", jsonKeys(decoded))
	}
	secretMap, ok := secretRaw.(map[string]any)
	if !ok {
		t.Fatalf("'secret' is not an object: %T", secretRaw)
	}

	// value nested inside secret.
	got, ok := secretMap["value"]
	if !ok {
		t.Fatalf("secret.value missing; secret keys: %v", jsonKeys(secretMap))
	}
	if got != "abc123" {
		t.Errorf("secret.value = %q, want %q", got, "abc123")
	}
}

// TestSecretRevealJSONBinaryValueBase64NestedInSecret verifies that binary
// (non-UTF-8) values also nest value_base64 inside "secret" rather than at
// the top level. We exercise this via secretGetJSONPayload directly since
// standing up a vault with a binary file secret is platform-sensitive.
func TestSecretRevealJSONBinaryValueBase64NestedInSecret(t *testing.T) {
	meta := secretMetadataView{Name: "BIN_KEY", Kind: "file"}
	binaryValue := []byte{0xff, 0xfe, 0xfd} // not valid UTF-8

	payload := secretGetJSONPayload(meta, false, true, binaryValue)

	// Top-level value_base64 must NOT exist.
	if _, ok := payload["value_base64"]; ok {
		t.Errorf("top-level 'value_base64' must not exist after migration; payload=%v", payload)
	}

	// value_base64 must be nested inside secret.
	var secretMap map[string]any
	switch s := payload["secret"].(type) {
	case map[string]any:
		secretMap = s
	default:
		b, _ := json.Marshal(s)
		if err := json.Unmarshal(b, &secretMap); err != nil {
			t.Fatalf("'secret' is not a map: %T", payload["secret"])
		}
	}
	if _, ok := secretMap["value_base64"]; !ok {
		t.Errorf("secret.value_base64 missing for binary content; secret keys: %v", jsonKeys(secretMap))
	}
	if _, ok := secretMap["value"]; ok {
		t.Errorf("secret.value must not exist for binary content (should use value_base64)")
	}
}

// TestSecretGetJSONPayloadValueNestedInSecret exercises secretGetJSONPayload
// directly (unit test on the helper function) so regressions are caught
// without needing a full vault round-trip.
func TestSecretGetJSONPayloadValueNestedInSecret(t *testing.T) {
	meta := secretMetadataView{Name: "TEST_KEY", Kind: "kv"}

	// reveal=true, utf-8 value → secret.value nested.
	payload := secretGetJSONPayload(meta, false, true, []byte("s3cr3t"))
	if _, exists := payload["value"]; exists {
		t.Errorf("top-level 'value' must not exist after migration; payload=%v", payload)
	}
	secretMap, ok := payload["secret"].(map[string]any)
	if !ok {
		// Fall back: maybe it's the struct form; try type assertion via JSON round-trip.
		b, _ := json.Marshal(payload["secret"])
		if err := json.Unmarshal(b, &secretMap); err != nil {
			t.Fatalf("'secret' value is not a map: %T", payload["secret"])
		}
	}
	if secretMap["value"] != "s3cr3t" {
		t.Errorf("secret.value = %q, want %q", secretMap["value"], "s3cr3t")
	}

	// reveal=false → no value anywhere.
	payloadNoReveal := secretGetJSONPayload(meta, false, false, nil)
	if _, exists := payloadNoReveal["value"]; exists {
		t.Errorf("top-level 'value' must not exist when reveal=false; payload=%v", payloadNoReveal)
	}
	secretMapNR, ok := payloadNoReveal["secret"].(map[string]any)
	if ok {
		if _, exists := secretMapNR["value"]; exists {
			t.Errorf("secret.value must not exist when reveal=false")
		}
	}
}

// --- ISSUE 2: trailing newline ---

// TestSecretRevealNoNewlineOnNonTTY confirms that when stdout is a bytes.Buffer
// (non-TTY) the output ends EXACTLY at the last value byte with no 0x0a.
// This is the "hasp secret reveal X | xxd" case — no phantom newline.
func TestSecretRevealNoNewlineOnNonTTY(t *testing.T) {
	revealSetup(t)
	var out bytes.Buffer
	if err := Run(context.Background(),
		[]string{"secret", "reveal", "API_TOKEN"},
		bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("secret reveal: %v", err)
	}
	// bytes.Buffer is not a TTY → must not end with 0x0a.
	raw := out.Bytes()
	if len(raw) == 0 {
		t.Fatal("reveal produced empty output")
	}
	if raw[len(raw)-1] == '\n' {
		t.Errorf("non-TTY reveal must not end with 0x0a; got trailing newline. "+
			"Full output (hex): % x", raw)
	}
	if string(raw) != "abc123" {
		t.Errorf("reveal output = %q, want exactly %q (no trailing newline)", string(raw), "abc123")
	}
}

// TestSecretRevealNewlineOnTTY confirms that when the secretRevealIsTTYFn seam
// is stubbed to return true a trailing newline is appended.
func TestSecretRevealNewlineOnTTY(t *testing.T) {
	revealSetup(t)

	// Stub TTY seam to simulate terminal.
	orig := secretRevealIsTTYFn
	secretRevealIsTTYFn = func(io.Writer) bool { return true }
	defer func() { secretRevealIsTTYFn = orig }()

	var out bytes.Buffer
	if err := Run(context.Background(),
		[]string{"secret", "reveal", "API_TOKEN"},
		bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("secret reveal (tty): %v", err)
	}
	raw := out.Bytes()
	if len(raw) == 0 {
		t.Fatal("reveal produced empty output")
	}
	if raw[len(raw)-1] != '\n' {
		t.Errorf("TTY reveal must end with newline; got % x", raw)
	}
	if strings.TrimRight(string(raw), "\n") != "abc123" {
		t.Errorf("reveal value before newline = %q, want %q", strings.TrimRight(string(raw), "\n"), "abc123")
	}
}

// TestSecretRevealNewlineFlagForcesNewline confirms --newline appends a
// trailing newline regardless of TTY state (TTY seam returns false here).
func TestSecretRevealNewlineFlagForcesNewline(t *testing.T) {
	revealSetup(t)
	var out bytes.Buffer
	if err := Run(context.Background(),
		[]string{"secret", "reveal", "--newline", "API_TOKEN"},
		bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("secret reveal --newline: %v", err)
	}
	raw := out.Bytes()
	if len(raw) == 0 {
		t.Fatal("reveal produced empty output")
	}
	if raw[len(raw)-1] != '\n' {
		t.Errorf("--newline flag must force trailing newline; got % x", raw)
	}
}

// TestSecretRevealNoNewlineFlagSuppressesNewline confirms --no-newline strips
// the trailing newline even when TTY seam returns true.
func TestSecretRevealNoNewlineFlagSuppressesNewline(t *testing.T) {
	revealSetup(t)

	orig := secretRevealIsTTYFn
	secretRevealIsTTYFn = func(io.Writer) bool { return true }
	defer func() { secretRevealIsTTYFn = orig }()

	var out bytes.Buffer
	if err := Run(context.Background(),
		[]string{"secret", "reveal", "--no-newline", "API_TOKEN"},
		bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("secret reveal --no-newline: %v", err)
	}
	raw := out.Bytes()
	if len(raw) == 0 {
		t.Fatal("reveal produced empty output")
	}
	if raw[len(raw)-1] == '\n' {
		t.Errorf("--no-newline flag must suppress trailing newline; got % x", raw)
	}
}

// --- helpers ---

func jsonKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
