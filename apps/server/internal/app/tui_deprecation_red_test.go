package app

// hasp-xh4b: `hasp tui` claims to open a terminal UI but actually
// emits a one-shot key/value snapshot — that mismatch costs trust.
// We don't want to ship a real Bubble Tea TUI yet (out of scope; new
// dependency, weeks of UX), so we mark `tui` as deprecated, print a
// warning to stderr pointing users at `hasp project status` (which
// already provides the structured project view), and update the help
// body to honestly describe what `tui` does.

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTUIPrintsDeprecationWarningOnInvocation(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "test-password-123")
	tempDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(tempDir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), []string{"tui", "--project-root", tempDir}, bytes.NewBuffer(nil), &stdout, &stderr); err != nil {
		t.Fatalf("Run tui: %v", err)
	}

	stderrStr := stderr.String()
	for _, want := range []string{"deprecated", "project status"} {
		if !strings.Contains(strings.ToLower(stderrStr), strings.ToLower(want)) {
			t.Fatalf("`hasp tui` must warn that it's deprecated and recommend `hasp project status`; missing %q in stderr=%q",
				want, stderrStr)
		}
	}
	// Existing snapshot output must still print to stdout — back-compat.
	if !strings.Contains(stdout.String(), "HASP TUI") && !strings.Contains(stdout.String(), "vault_items") {
		t.Fatalf("`hasp tui` must keep emitting its snapshot for back-compat; got stdout=%q", stdout.String())
	}
}

func TestTUIHelpBodyHonestlyDescribesItsBehavior(t *testing.T) {
	body, ok := helpTopicByKey["tui"]
	if !ok {
		t.Fatalf("missing help topic for tui")
	}
	lower := strings.ToLower(body)
	for _, want := range []string{"deprecated", "project status"} {
		if !strings.Contains(lower, want) {
			t.Fatalf("`hasp help tui` must mention deprecation and the recommended replacement; missing %q in body:\n%s",
				want, body)
		}
	}
	// And it must NOT promise an interactive UI.
	if strings.Contains(lower, "interactive") || strings.Contains(lower, "open the terminal ui") {
		t.Fatalf("`hasp help tui` must not promise an interactive UI; body:\n%s", body)
	}
}
