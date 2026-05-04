package app

// Red-team tests for hasp-x05.1.2: Surface exact brokered proof command and
// verification state with explicit state strings.  All assertions reflect
// acceptance criteria defined in the hasp-x05 task spec.  These tests MUST
// fail until the green team implements the required behaviour.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// TestBrokeredProofStateNoProjectRoot asserts that setupVerifyBrokeredProof
// returns state="unavailable" with reason="no project root" when called with
// an empty project root.  The current implementation does not set a "state"
// key, so this test must fail.
func TestBrokeredProofStateNoProjectRoot(t *testing.T) {
	result, err := setupVerifyBrokeredProof(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, _ := result["state"].(string)
	if state != "unavailable" {
		t.Fatalf("expected state=%q, got %q (full result: %#v)", "unavailable", state, result)
	}
	reason, _ := result["reason"].(string)
	if reason != "no project root" {
		t.Fatalf("expected reason=%q, got %q", "no project root", reason)
	}
}

// TestBrokeredProofStateNoReference asserts that setupVerifyBrokeredProof
// returns state="unavailable", reason="no brokered reference available yet",
// AND a rescue map with available=true and a non-empty commands slice
// containing inline rescue options when there are no bound references.
func TestBrokeredProofStateNoReference(t *testing.T) {
	result, err := setupVerifyBrokeredProof(context.Background(), "/tmp/repo", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, _ := result["state"].(string)
	if state != "unavailable" {
		t.Fatalf("expected state=%q, got %q (full result: %#v)", "unavailable", state, result)
	}
	reason, _ := result["reason"].(string)
	if reason != "no brokered reference available yet" {
		t.Fatalf("expected reason=%q, got %q", "no brokered reference available yet", reason)
	}

	rescue, ok := result["rescue"].(map[string]any)
	if !ok {
		t.Fatalf("expected rescue map, got %T: %#v", result["rescue"], result["rescue"])
	}
	if rescue["available"] != true {
		t.Fatalf("expected rescue.available=true, got %#v", rescue["available"])
	}
	cmds, ok := rescue["commands"].([]string)
	if !ok {
		// also accept []any
		rawCmds, ok2 := rescue["commands"].([]any)
		if !ok2 || len(rawCmds) == 0 {
			t.Fatalf("expected rescue.commands non-empty slice, got %T: %#v", rescue["commands"], rescue["commands"])
		}
		for _, c := range rawCmds {
			cmds = append(cmds, c.(string))
		}
	}
	if len(cmds) == 0 {
		t.Fatalf("expected rescue.commands to be non-empty")
	}
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "hasp secret add") && !strings.Contains(joined, "hasp import") {
		t.Fatalf("expected rescue.commands to contain hasp secret add or hasp import, got %q", joined)
	}
}

// TestBrokeredProofStateReady asserts that setupVerifyBrokeredProof returns
// state="ready" with a non-empty reference and a command equal to
// setupBrokeredProofCommand that contains no "<repo>" placeholder when a
// visible reference is available.
func TestBrokeredProofStateReady(t *testing.T) {
	lockAppSeams(t)
	origStarter := newRuntimeStarterFn
	t.Cleanup(func() { newRuntimeStarterFn = origStarter })
	newRuntimeStarterFn = func() (*runtimeStarter, error) { return nil, errors.New("no-op for red test") }

	visible := []store.VisibleReference{{Alias: "secret_01"}}
	result, err := setupVerifyBrokeredProof(context.Background(), "/tmp/repo", visible)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, _ := result["state"].(string)
	if state != "ready" {
		t.Fatalf("expected state=%q, got %q (full result: %#v)", "ready", state, result)
	}
	ref, _ := result["reference"].(string)
	if ref == "" {
		t.Fatalf("expected non-empty reference, got %q", ref)
	}
	cmd, _ := result["command"].(string)
	expectedCmd := setupBrokeredProofCommand("/tmp/repo", ref)
	if cmd != expectedCmd {
		t.Fatalf("expected command=%q, got %q", expectedCmd, cmd)
	}
	if strings.Contains(cmd, "<repo>") {
		t.Fatalf("command must not contain <repo> placeholder, got %q", cmd)
	}
}

// TestBrokeredProofRescueInHumanSummaryWhenUnavailable asserts that
// renderSetupSummary outputs lines containing inline rescue commands
// (hasp secret add or hasp import) when brokered_proof state is
// "unavailable" with reason "no brokered reference available yet".
func TestBrokeredProofRescueInHumanSummaryWhenUnavailable(t *testing.T) {
	var out bytes.Buffer
	summary := setupSummary{
		HaspHome:          "/tmp/.hasp",
		ConfigPath:        "/tmp/.config/hasp-cli.json",
		InitState:         "created",
		ConvenienceUnlock: "disabled",
		Verification: map[string]any{
			"brokered_proof": map[string]any{
				"performed": false,
				"ready":     false,
				"state":     "unavailable",
				"reason":    "no brokered reference available yet",
				"rescue": map[string]any{
					"available": true,
					"commands":  []string{"hasp secret add --bind <name> <file>", "hasp import --bind .env"},
				},
			},
		},
	}
	if err := renderSetupSummary(&out, summary); err != nil {
		t.Fatalf("renderSetupSummary: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "hasp secret add") && !strings.Contains(text, "hasp import") {
		t.Fatalf("expected human summary to contain inline rescue commands (hasp secret add or hasp import), got:\n%s", text)
	}
}

// TestBrokeredProofHumanSummaryShowsReadyAfterRescue asserts that when a
// rescue has been applied (performed=true, ready=true, non-empty reference),
// the human summary shows the ready proof command, not just "skipped" or empty.
func TestBrokeredProofHumanSummaryShowsReadyAfterRescue(t *testing.T) {
	var out bytes.Buffer
	summary := setupSummary{
		HaspHome:          "/tmp/.hasp",
		ConfigPath:        "/tmp/.config/hasp-cli.json",
		InitState:         "created",
		ConvenienceUnlock: "disabled",
		Verification: map[string]any{
			"brokered_proof": map[string]any{
				"performed": true,
				"ready":     true,
				"state":     "ready",
				"reference": "secret_01",
				"command":   setupBrokeredProofCommand("/tmp/repo", "secret_01"),
				"rescue": map[string]any{
					"available":    false,
					"performed":    true,
					"next_command": setupBrokeredProofCommand("/tmp/repo", "secret_01"),
				},
			},
		},
	}
	if err := renderSetupSummary(&out, summary); err != nil {
		t.Fatalf("renderSetupSummary: %v", err)
	}
	text := out.String()
	// After rescue, the summary must surface the concrete proof command
	if !strings.Contains(text, setupBrokeredProofCommand("/tmp/repo", "secret_01")) {
		t.Fatalf("expected human summary to contain the ready proof command after rescue, got:\n%s", text)
	}
}
