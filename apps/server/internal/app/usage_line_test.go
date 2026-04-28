package app

import (
	"strings"
	"testing"
)

// hasp-28um: setup usage error must enumerate every FlagSet-declared flag,
// not the hand-curated subset that drifted to 6 of 17.
func TestParseSetupOptionsUsageLineCoversEverySupportedFlag(t *testing.T) {
	_, _, err := parseSetupOptions([]string{"trailing-positional"})
	if err == nil {
		t.Fatal("expected usage error from trailing positional")
	}
	msg := err.Error()
	expectedFlags := []string{
		"--non-interactive",
		"--json",
		"--hasp-home",
		"--repo",
		"--project-root",
		"--master-password-env",
		"--master-password-stdin",
		"--import",
		"--import-format",
		"--bind-imports",
		"--default-policy",
		"--skip-password-policy",
		"--agent",
		"--bind-item",
		"--alias",
		"--auto-protect-repos",
		"--install-hooks",
		"--enable-convenience-unlock",
		"--overwrite-existing-config",
	}
	for _, want := range expectedFlags {
		if !strings.Contains(msg, want) {
			t.Errorf("usage error missing flag %q: %s", want, msg)
		}
	}
}
