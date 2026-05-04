package app

// RED tests for hasp-ohub — surface redactor_min_length in human doctor only.
//
// Contract pinned (not yet implemented):
//   - `hasp doctor --json` remains strict agent-safe schema output and does
//     not expose redactor tuning details.
//   - Human doctor output may include redactor diagnostics for operators.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
)

func TestDoctorJSONOmitsRedactorMinLength(t *testing.T) {
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

	if _, ok := out["redactor_min_length"]; ok {
		t.Fatalf("doctor --json must not expose redactor_min_length; got keys: %v", mapKeys(out))
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
