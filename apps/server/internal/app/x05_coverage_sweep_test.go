package app

// Coverage sweep for branches introduced or left uncovered after hasp-x05:
// - audit_human_modes.go: nil-guard + defensive branches in redactDetailsForHuman,
//   isBlocked, and the timeline writer error path.
// - bootstrap_print_config.go: all four error/arg-parsing branches.
// - secrets.go: audit --blocked / --since / --format error paths.
// - setup.go: setupVerifyBrokeredProofFn error fallback in runSetup is covered by
//   TestRunSetupBrokeredProofErrorFallback.
// - setup_finalize.go: setupFirstExecutableProofReference fallback to NamedReference.
// - setup_ui.go: ready-without-state, []any rescue commands, and writer-error
//   returns in the rescue + proof-command surfacing branches.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestRedactDetailsForHumanNil(t *testing.T) {
	if got := redactDetailsForHuman(nil); got != nil {
		t.Fatalf("expected nil passthrough, got %#v", got)
	}
}

func TestIsBlockedVariants(t *testing.T) {
	if isBlocked(nil) {
		t.Fatal("expected false for nil details")
	}
	if !isBlocked(map[string]any{"blocked": "true"}) {
		t.Fatal("expected true for string blocked")
	}
	if isBlocked(map[string]any{"blocked": "nope"}) {
		t.Fatal("expected false for non-true string")
	}
	if isBlocked(map[string]any{"blocked": 123}) {
		t.Fatal("expected false for unsupported type")
	}
	if isBlocked(map[string]any{"other": true}) {
		t.Fatal("expected false when key missing")
	}
}

func TestAuditRenderTimelineWriterError(t *testing.T) {
	events := []audit.Event{{
		Timestamp: time.Unix(1, 0).UTC(),
		Type:      "inject",
		Actor:     "codex-cli",
		Details:   map[string]any{"reference": "secret_01", "blocked": true},
	}}
	w := errWriter{err: errors.New("write fail")}
	if err := auditRenderTimeline(events, w); err == nil {
		t.Fatal("expected error from failing writer")
	}
}

func TestBootstrapPrintConfigCommandArgErrors(t *testing.T) {
	var out bytes.Buffer

	if err := bootstrapPrintConfigCommand([]string{"generic-compatible", "--format"}, &out); err == nil {
		t.Fatal("expected error for --format with missing value")
	}

	out.Reset()
	if err := bootstrapPrintConfigCommand([]string{"--format=cursor-json", "generic-compatible"}, &out); err != nil {
		t.Fatalf("unexpected error for --format=cursor-json form: %v", err)
	}
	if !strings.Contains(out.String(), "generic-compatible") {
		t.Fatalf("expected cursor-json snippet, got %q", out.String())
	}

	out.Reset()
	if err := bootstrapPrintConfigCommand([]string{"wrong-target"}, &out); err == nil {
		t.Fatal("expected error for unknown target")
	}

	out.Reset()
	if err := bootstrapPrintConfigCommand([]string{"generic-compatible", "--format=bogus"}, &out); err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestAuditCommandBlockedFlagExplicit(t *testing.T) {
	lockAppSeams(t)
	origLog := newAuditLogFn
	origEvents := auditEventsFn
	t.Cleanup(func() {
		newAuditLogFn = origLog
		auditEventsFn = origEvents
	})
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) {
		return []audit.Event{
			{Type: "inject", Details: map[string]any{"blocked": true}},
			{Type: "inject", Details: map[string]any{"blocked": false}},
		}, nil
	}
	var out bytes.Buffer
	if err := auditCommandWithArgs([]string{"--json", "--blocked"}, &out); err != nil {
		t.Fatalf("audit --blocked: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, `"blocked"`) {
		t.Fatalf("expected blocked events in output, got %q", body)
	}
}

func TestAuditCommandSinceAcceptsRFC3339AndRejectsGarbage(t *testing.T) {
	lockAppSeams(t)
	origLog := newAuditLogFn
	origEvents := auditEventsFn
	t.Cleanup(func() {
		newAuditLogFn = origLog
		auditEventsFn = origEvents
	})
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return nil, nil }

	var out bytes.Buffer
	if err := auditCommandWithArgs([]string{"--json", "--since=2020-01-02T03:04:05Z"}, &out); err != nil {
		t.Fatalf("audit --since RFC3339: %v", err)
	}

	out.Reset()
	if err := auditCommandWithArgs([]string{"--since=not-a-time"}, &out); err == nil {
		t.Fatal("expected error for invalid --since value")
	}
}

func TestAuditCommandFormatTimelineEventsError(t *testing.T) {
	lockAppSeams(t)
	origLog := newAuditLogFn
	origEvents := auditEventsFn
	t.Cleanup(func() {
		newAuditLogFn = origLog
		auditEventsFn = origEvents
	})
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return nil, errors.New("events fail") }

	var out bytes.Buffer
	if err := auditCommandWithArgs([]string{"--format=timeline"}, &out); err == nil {
		t.Fatal("expected events error to propagate through timeline path")
	}
}

func TestSetupFirstExecutableProofReferenceFallsBackToNamedRef(t *testing.T) {
	ref := setupFirstExecutableProofReference([]store.VisibleReference{{NamedReference: "@API_TOKEN"}})
	if ref != "@API_TOKEN" {
		t.Fatalf("expected named reference fallback, got %q", ref)
	}
}

func TestRunSetupBrokeredProofErrorFallback(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	haspHome := filepath.Join(t.TempDir(), "hasp-home")
	projectRoot := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))
	t.Setenv("SETUP_PW", "correct horse battery staple")

	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
	setupLookPathFn = func(string) (string, error) { return "", os.ErrNotExist }
	setupVerifyBrokeredProofFn = func(_ context.Context, _ string, _ []store.VisibleReference) (map[string]any, error) {
		return nil, errors.New("harness offline")
	}

	opts := setupOptions{
		NonInteractive:          true,
		HaspHome:                haspHome,
		Repo:                    projectRoot,
		Agents:                  setupAgentFlags{""},
		PasswordEnv:             "SETUP_PW",
		InstallHooks:            setupOptionalBool{set: true, value: false},
		EnableConvenienceUnlock: setupOptionalBool{set: true, value: false},
		OverwriteExistingConfig: setupOptionalBool{set: true, value: true},
		DefaultPolicy:           store.PolicySession,
	}
	summary, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard)
	if err != nil {
		t.Fatalf("runSetup: %v", err)
	}
	proof, ok := summary.Verification["brokered_proof"].(map[string]any)
	if !ok {
		t.Fatalf("expected brokered_proof map, got %#v", summary.Verification["brokered_proof"])
	}
	if proof["reason"] != "harness offline" {
		t.Fatalf("expected reason=harness offline, got %#v", proof["reason"])
	}
	if proof["ready"] != false {
		t.Fatalf("expected ready=false on fallback, got %#v", proof["ready"])
	}
}

func TestRenderSetupSummaryReadyWithoutStateKey(t *testing.T) {
	var out bytes.Buffer
	summary := setupSummary{
		Verification: map[string]any{
			"brokered_proof": map[string]any{
				"performed": false,
				"ready":     true,
				"reference": "secret_01",
				"command":   `hasp run --project-root "/tmp/repo" ...`,
			},
		},
	}
	if err := renderSetupSummary(&out, summary); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(out.String(), "ready") {
		t.Fatalf("expected ready status on no-state-key proof map, got %q", out.String())
	}
}

func TestRenderSetupSummaryRescueWithAnyCommandsAndPerformed(t *testing.T) {
	var out bytes.Buffer
	summary := setupSummary{
		Verification: map[string]any{
			"brokered_proof": map[string]any{
				"performed": false,
				"ready":     false,
				"state":     "unavailable",
				"reason":    "no brokered reference available yet",
				"rescue": map[string]any{
					"available":    true,
					"reason":       "no brokered reference available yet",
					"commands":     []any{"hasp secret add --bind", 123, "hasp import --bind"},
					"next_command": "hasp run ...",
					"performed":    true,
				},
			},
		},
	}
	if err := renderSetupSummary(&out, summary); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, "hasp secret add --bind") {
		t.Fatalf("expected []any string rescue command to render, got %q", body)
	}
	if !strings.Contains(body, "Run the brokered proof") {
		t.Fatalf("expected rescue-performed surfaced next_command, got %q", body)
	}
}

type substringErrWriter struct {
	trigger string
	err     error
}

func (w substringErrWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.trigger) {
		return 0, w.err
	}
	return len(p), nil
}

func TestRenderSetupSummaryWriterErrorPaths(t *testing.T) {
	rescueSummary := func(commands any, performed bool) setupSummary {
		return setupSummary{
			Verification: map[string]any{
				"brokered_proof": map[string]any{
					"performed": false,
					"ready":     false,
					"state":     "unavailable",
					"reason":    "no brokered reference available yet",
					"rescue": map[string]any{
						"available":    true,
						"reason":       "no brokered reference available yet",
						"commands":     commands,
						"next_command": "hasp run --project-root /tmp/repo ...",
						"performed":    performed,
					},
				},
			},
		}
	}

	cases := []struct {
		name    string
		summary setupSummary
		trigger string
	}{
		{
			name:    "inline-rescue-header",
			summary: rescueSummary([]string{"hasp secret add --bind"}, false),
			trigger: "Inline rescue",
		},
		{
			name:    "rescue-command-string-slice",
			summary: rescueSummary([]string{"STRING_SLICE_COMMAND"}, false),
			trigger: "STRING_SLICE_COMMAND",
		},
		{
			name:    "rescue-command-any-slice",
			summary: rescueSummary([]any{"ANY_SLICE_COMMAND"}, false),
			trigger: "ANY_SLICE_COMMAND",
		},
		{
			name:    "rescue-performed-next-command",
			summary: rescueSummary([]string{"hasp secret add --bind"}, true),
			trigger: "Run the brokered proof",
		},
		{
			name: "ready-proof-command",
			summary: setupSummary{
				Verification: map[string]any{
					"brokered_proof": map[string]any{
						"performed": false,
						"ready":     true,
						"state":     "ready",
						"reference": "secret_01",
						"command":   "hasp run --project-root /tmp/repo ...",
					},
				},
			},
			trigger: "Proof command",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := substringErrWriter{trigger: tc.trigger, err: errors.New("write boom")}
			if err := renderSetupSummary(w, tc.summary); err == nil {
				t.Fatalf("expected write error for trigger %q", tc.trigger)
			}
		})
	}
}
