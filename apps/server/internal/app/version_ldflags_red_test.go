package app

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	apsruntime "github.com/gethasp/hasp/apps/server/internal/runtime"
)

// TestVersionLDFlagsInjectedValues verifies that when the ldflags package
// variables (Commit, BuildDate) are set to non-default values, the version
// JSON output correctly reflects those values with the expected keys.
//
// This is the GREEN half: the vars are exported and directly settable,
// so any build that injects them via -X will be visible here at runtime.
func TestVersionLDFlagsInjectedValues(t *testing.T) {
	lockAppSeams(t)

	origCommit := apsruntime.Commit
	origBuildDate := apsruntime.BuildDate
	t.Cleanup(func() {
		apsruntime.Commit = origCommit
		apsruntime.BuildDate = origBuildDate
	})

	apsruntime.Commit = "abc12345"
	apsruntime.BuildDate = "2026-04-26T12:00:00Z"

	var buf bytes.Buffer
	if err := versionCommand(context.Background(), []string{"--json"}, &buf); err != nil {
		t.Fatalf("versionCommand --json: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("decode --json payload: %v\nraw: %s", err, buf.String())
	}

	// Key shape must be present.
	for _, key := range []string{"commit", "build_date"} {
		if _, ok := payload[key]; !ok {
			t.Errorf("missing key %q in payload: %v", key, payload)
		}
	}

	if got := payload["commit"]; got != "abc12345" {
		t.Errorf("commit: want %q, got %v", "abc12345", got)
	}
	if got := payload["build_date"]; got != "2026-04-26T12:00:00Z" {
		t.Errorf("build_date: want %q, got %v", "2026-04-26T12:00:00Z", got)
	}
}

// TestVersionLDFlagsFallbackUnknown verifies that when ldflags are not
// injected (Commit == "unknown", BuildDate == "unknown"), the JSON output
// still emits a valid, informative payload — not blank or missing fields.
func TestVersionLDFlagsFallbackUnknown(t *testing.T) {
	lockAppSeams(t)

	origCommit := apsruntime.Commit
	origBuildDate := apsruntime.BuildDate
	t.Cleanup(func() {
		apsruntime.Commit = origCommit
		apsruntime.BuildDate = origBuildDate
	})

	apsruntime.Commit = "unknown"
	apsruntime.BuildDate = "unknown"

	var buf bytes.Buffer
	if err := versionCommand(context.Background(), []string{"--json"}, &buf); err != nil {
		t.Fatalf("versionCommand --json: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("decode --json payload: %v\nraw: %s", err, buf.String())
	}

	// Both keys must be present and non-empty even in fallback mode.
	for _, key := range []string{"commit", "build_date"} {
		v, ok := payload[key]
		if !ok {
			t.Errorf("missing key %q in fallback payload", key)
			continue
		}
		s, _ := v.(string)
		if s == "" {
			t.Errorf("key %q must not be empty string in fallback payload", key)
		}
	}

	if got := payload["commit"]; got != "unknown" {
		t.Errorf("commit fallback: want %q, got %v", "unknown", got)
	}
	if got := payload["build_date"]; got != "unknown" {
		t.Errorf("build_date fallback: want %q, got %v", "unknown", got)
	}
}
