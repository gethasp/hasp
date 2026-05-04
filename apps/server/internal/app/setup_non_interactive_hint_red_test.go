package app

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestSetupNonInteractiveHint verifies that when non-interactive setup is
// invoked with no master password source, the error message explicitly names
// HASP_MASTER_PASSWORD and includes actionable wording ("set" or "export").
func TestSetupNonInteractiveHint(t *testing.T) {
	lockAppSeams(t)

	// Ensure HASP_MASTER_PASSWORD is not set so the test is clean-room.
	t.Setenv("HASP_MASTER_PASSWORD", "")

	// Test 1: setupResolvePassword defensive path (NonInteractive=true, no password source).
	_, _, err := setupResolvePassword(
		newSetupPrompter(bytes.NewBuffer(nil), io.Discard),
		setupOptions{NonInteractive: true},
		t.TempDir(),
	)
	if err == nil {
		t.Fatal("expected error from setupResolvePassword with NonInteractive=true and no password source")
	}
	msg := err.Error()
	if !strings.Contains(msg, "HASP_MASTER_PASSWORD") {
		t.Errorf("error message must contain HASP_MASTER_PASSWORD; got: %q", msg)
	}
	if !strings.Contains(msg, "set") && !strings.Contains(msg, "export") {
		t.Errorf("error message must contain actionable wording (\"set\" or \"export\"); got: %q", msg)
	}

	// Test 2: validateSetupNonInteractive path (the primary validation gate).
	err2 := validateSetupNonInteractive(setupOptions{
		NonInteractive: true,
		HaspHome:       "/tmp/hasp-home",
		// PasswordEnv and PasswordStdin intentionally unset.
	})
	if err2 == nil {
		t.Fatal("expected error from validateSetupNonInteractive with no password source")
	}
	msg2 := err2.Error()
	if !strings.Contains(msg2, "HASP_MASTER_PASSWORD") {
		t.Errorf("validateSetupNonInteractive error must contain HASP_MASTER_PASSWORD; got: %q", msg2)
	}
	if !strings.Contains(msg2, "set") && !strings.Contains(msg2, "export") {
		t.Errorf("validateSetupNonInteractive error must contain actionable wording (\"set\" or \"export\"); got: %q", msg2)
	}
}
