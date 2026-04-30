package app

// Red-team tests for hasp-x05.1.1: Inline rescue when setup has no managed
// ref.  These tests assert the rescue lane is surfaced in setupSummary via
// Verification.brokered_proof with the required keys (state, rescue map with
// available, reason, commands, next_command).  All assertions must fail until
// the green team delivers the implementation.

import (
	"context"
	"strings"
	"testing"
)

// TestSetupSummaryVerificationBrokeredProofHasRescueKeys asserts that when
// brokered_proof.state is "unavailable" with reason "no brokered reference
// available yet", the verification map must include a "rescue" map with:
//   - available == true
//   - non-empty "reason" string
//   - "commands" list containing at least one entry
//   - "next_command" that matches setupBrokeredProofCommand once a ref exists
func TestSetupSummaryVerificationBrokeredProofHasRescueKeys(t *testing.T) {
	result, err := setupVerifyBrokeredProof(context.Background(), "/tmp/repo", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The new "state" key must exist
	if _, ok := result["state"]; !ok {
		t.Fatalf("expected 'state' key in brokered_proof result, got %#v", result)
	}

	// rescue block must exist
	rescue, ok := result["rescue"].(map[string]any)
	if !ok {
		t.Fatalf("expected 'rescue' map in brokered_proof result, got %T: %#v", result["rescue"], result["rescue"])
	}

	if rescue["available"] != true {
		t.Fatalf("expected rescue.available=true, got %#v", rescue["available"])
	}
	rescueReason, _ := rescue["reason"].(string)
	if strings.TrimSpace(rescueReason) == "" {
		t.Fatalf("expected rescue.reason to be non-empty")
	}

	var cmds []string
	switch v := rescue["commands"].(type) {
	case []string:
		cmds = v
	case []any:
		for _, c := range v {
			s, ok := c.(string)
			if !ok {
				t.Fatalf("rescue.commands element not a string: %T %#v", c, c)
			}
			cmds = append(cmds, s)
		}
	default:
		t.Fatalf("expected rescue.commands to be a slice, got %T: %#v", rescue["commands"], rescue["commands"])
	}
	if len(cmds) == 0 {
		t.Fatalf("expected rescue.commands to be non-empty")
	}

	// next_command must be present and match setupBrokeredProofCommand once a
	// ref is bound — for the no-ref case it should be non-empty but may be a
	// template; we just require it is present.
	if _, ok := rescue["next_command"]; !ok {
		t.Fatalf("expected rescue.next_command key in rescue map, got %#v", rescue)
	}
}

// TestSetupSummaryVerificationRescueNextCommandMatchesBrokeredProof asserts
// that the no-ref rescue block surfaces a next_command equal to
// setupBrokeredProofCommand(root, "@SECRET_NAME") so the two derivations stay
// consistent.
func TestSetupSummaryVerificationRescueNextCommandMatchesBrokeredProof(t *testing.T) {
	const root = "/tmp/testrepo"
	result, err := setupVerifyBrokeredProof(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rescue, ok := result["rescue"].(map[string]any)
	if !ok {
		t.Fatalf("expected rescue map, got %#v", result["rescue"])
	}
	got, _ := rescue["next_command"].(string)
	expected := setupBrokeredProofCommand(root, "@SECRET_NAME")
	if got != expected {
		t.Fatalf("expected rescue.next_command=%q, got %q", expected, got)
	}
}

// TestSetupSummaryVerificationHasStateKey confirms that the brokered_proof
// result from setupVerifyBrokeredProof always has a "state" key (never just
// "reason" alone).  This is a structural regression guard.
func TestSetupSummaryVerificationHasStateKey(t *testing.T) {
	cases := []struct {
		name        string
		projectRoot string
		visible     interface{}
		wantState   string
	}{
		{"no-root", "", nil, "unavailable"},
		{"no-ref", "/tmp/repo", nil, "unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := setupVerifyBrokeredProof(context.Background(), tc.projectRoot, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			state, _ := result["state"].(string)
			if state != tc.wantState {
				t.Fatalf("case %s: expected state=%q, got %q (result: %#v)", tc.name, tc.wantState, state, result)
			}
		})
	}
}
