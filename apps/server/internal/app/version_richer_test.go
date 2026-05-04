package app

import (
	"bytes"
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

// TestVersionCommandRichJSONPayload verifies that `hasp version --json`
// emits the operator-relevant build/runtime fields callers need to reason
// about a binary in production: version, commit, build_date, go_version,
// format_version, os, and arch. Pretty mode stays one line for
// grep-friendliness. KDF tuning fields are gated behind --verbose
// (hasp-y6sg) so default scripts can't fingerprint weakened builds.
func TestVersionCommandRichJSONPayload(t *testing.T) {
	lockAppSeams(t)

	var buf bytes.Buffer
	if err := versionCommand(context.Background(), []string{"--json"}, &buf); err != nil {
		t.Fatalf("versionCommand --json: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("decode --json payload: %v\nraw: %s", err, buf.String())
	}

	required := []string{
		"version",
		"commit",
		"build_date",
		"go_version",
		"format_version",
		"os",
		"arch",
		"upgrade_trust_roots",
	}
	for _, key := range required {
		if _, ok := payload[key]; !ok {
			t.Errorf("missing key %q in --json payload: %v", key, payload)
		}
	}

	if got := payload["go_version"]; got != runtime.Version() {
		t.Errorf("go_version: want %q, got %v", runtime.Version(), got)
	}
	if got := payload["os"]; got != runtime.GOOS {
		t.Errorf("os: want %q, got %v", runtime.GOOS, got)
	}
	if got := payload["arch"]; got != runtime.GOARCH {
		t.Errorf("arch: want %q, got %v", runtime.GOARCH, got)
	}
	if got, _ := payload["format_version"].(float64); got <= 0 {
		t.Errorf("format_version must be positive, got %v", payload["format_version"])
	}
	if got, ok := payload["upgrade_trust_roots"].(bool); !ok || got {
		t.Errorf("dev/test build should report upgrade_trust_roots=false, got %v", payload["upgrade_trust_roots"])
	}

	// Default mode must NOT leak KDF tuning details.
	for _, key := range []string{"default_kdf", "default_kdf_iterations", "default_kdf_time", "default_kdf_memory_kib", "default_kdf_parallelism"} {
		if _, present := payload[key]; present {
			t.Errorf("expected %q to be gated behind --verbose, but it appeared in default payload", key)
		}
	}
}

// TestVersionCommandVerboseExposesKDFParams: --verbose surfaces KDF tuning
// for diagnostics (operators running `hasp version --json --verbose`),
// matching what `hasp doctor` reports.
func TestVersionCommandVerboseExposesKDFParams(t *testing.T) {
	lockAppSeams(t)

	ctx := contextWithGlobalFlags(context.Background(), globalFlags{verbose: true})
	var buf bytes.Buffer
	if err := versionCommand(ctx, []string{"--json"}, &buf); err != nil {
		t.Fatalf("versionCommand --json --verbose: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("decode --json payload: %v\nraw: %s", err, buf.String())
	}
	if got, _ := payload["default_kdf"].(string); got == "" {
		t.Errorf("default_kdf must not be empty under --verbose")
	}
	if got, _ := payload["default_kdf_iterations"].(float64); got <= 0 {
		t.Errorf("default_kdf_iterations must be positive under --verbose, got %v", payload["default_kdf_iterations"])
	}
}

// TestVersionCommandHumanStaysSingleLine guards the contract that pretty
// output remains a single trimmed line — `hasp version` in scripts and
// monospace renderers should not balloon into a multi-line block.
func TestVersionCommandHumanStaysSingleLine(t *testing.T) {
	lockAppSeams(t)

	var buf bytes.Buffer
	if err := versionCommand(context.Background(), nil, &buf); err != nil {
		t.Fatalf("versionCommand: %v", err)
	}
	got := strings.TrimRight(buf.String(), "\n")
	if strings.Contains(got, "\n") {
		t.Fatalf("expected single-line pretty output, got %q", got)
	}
	if got == "" {
		t.Fatal("expected non-empty version output")
	}
}
