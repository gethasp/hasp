package app

// RED tests for hasp-ohub — surface redactor_min_length in hasp doctor --json.
//
// Contract pinned (not yet implemented):
//   - `hasp doctor --json` output includes a top-level field
//     "redactor_min_length" with value 6 (the current minRedactLen constant).
//   - The field is present regardless of daemon / vault state so operators
//     always know the active threshold without reading source code.
//
// These tests are intentionally RED: doctorJSONReport does not yet carry this
// field. GREEN phase must add RedactorMinLength to doctorJSONReport and wire it
// through buildDoctorReport / doctorCommand.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
)

func TestDoctorJSONIncludesRedactorMinLength(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	_ = initCommandWithArgs(context.Background(), nil, io.Discard)

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"doctor", "--json"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("doctor --json: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal doctor JSON: %v (output: %s)", err, stdout.String())
	}

	raw, ok := out["redactor_min_length"]
	if !ok {
		t.Fatalf("doctor --json missing field 'redactor_min_length'; got keys: %v", mapKeys(out))
	}

	// JSON numbers unmarshal as float64.
	val, ok := raw.(float64)
	if !ok {
		t.Fatalf("expected 'redactor_min_length' to be a number, got %T (%v)", raw, raw)
	}
	const wantMinLen = 6
	if int(val) != wantMinLen {
		t.Fatalf("expected redactor_min_length=%d, got %v", wantMinLen, val)
	}
}

func TestDoctorHumanOutputMentionsRedactorMinLength(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	_ = initCommandWithArgs(context.Background(), nil, io.Discard)

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"doctor"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("doctor: %v", err)
	}

	out := stdout.String()
	if !containsAny(out, "redactor_min_length", "redact_min_len", "min_redact_len") {
		t.Fatalf("doctor human output does not mention redactor min length; got:\n%s", out)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
