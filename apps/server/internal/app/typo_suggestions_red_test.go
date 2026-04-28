package app

// hasp-tzx8: typo suggestions for unknown help topics, root commands, and
// subcommands. Uses Levenshtein distance so "hasp help secrt" → "did you
// mean: secret".

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// runTypoTest is a convenience wrapper that runs hasp with the given args and
// returns (stdout+stderr text, error).
func runTypoTest(t *testing.T, args ...string) (string, error) {
	t.Helper()
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "not-used-in-these-tests")

	var stdout, stderr bytes.Buffer
	err := runWithStarter(context.Background(), args, bytes.NewReader(nil), &stdout, &stderr, &fakeStarter{})
	combined := stdout.String() + stderr.String()
	return combined, err
}

// TestTypoHelpTopicSuggestion checks that a near-miss help topic emits a
// "did you mean: secret" suggestion.
func TestTypoHelpTopicSuggestion(t *testing.T) {
	out, err := runTypoTest(t, "help", "secrt")
	if err == nil {
		t.Fatalf("expected error for unknown help topic, got nil; output=%q", out)
	}
	lower := strings.ToLower(err.Error() + out)
	if !strings.Contains(lower, "did you mean") {
		t.Fatalf("expected 'did you mean' in output for 'hasp help secrt'; got err=%q output=%q", err, out)
	}
	if !strings.Contains(lower, "secret") {
		t.Fatalf("expected suggestion 'secret' in output for 'hasp help secrt'; got err=%q output=%q", err, out)
	}
}

// TestTypoHelpTopicNoSuggestionForGibberish checks that a completely unknown
// help topic does NOT produce a false "did you mean" suggestion.
func TestTypoHelpTopicNoSuggestionForGibberish(t *testing.T) {
	out, err := runTypoTest(t, "help", "xxxxx")
	if err == nil {
		t.Fatalf("expected error for unknown help topic, got nil; output=%q", out)
	}
	lower := strings.ToLower(err.Error() + out)
	if strings.Contains(lower, "did you mean") {
		t.Fatalf("unexpected 'did you mean' suggestion for 'hasp help xxxxx'; got err=%q output=%q", err, out)
	}
}

// TestTypoRootCommandSuggestion checks that a typo of a root command emits a
// suggestion via "did you mean".
func TestTypoRootCommandSuggestion(t *testing.T) {
	out, err := runTypoTest(t, "seeret", "list")
	if err == nil {
		t.Fatalf("expected error for unknown root command, got nil; output=%q", out)
	}
	lower := strings.ToLower(err.Error() + out)
	if !strings.Contains(lower, "did you mean") {
		t.Fatalf("expected 'did you mean' for root command typo 'seeret'; got err=%q output=%q", err, out)
	}
	if !strings.Contains(lower, "secret") {
		t.Fatalf("expected suggestion 'secret' for root command typo 'seeret'; got err=%q output=%q", err, out)
	}
}

// TestTypoSubcommandSuggestion checks that a typo of a subcommand name emits a
// suggestion via "did you mean".
func TestTypoSubcommandSuggestion(t *testing.T) {
	out, err := runTypoTest(t, "secret", "lsit")
	if err == nil {
		t.Fatalf("expected error for unknown subcommand, got nil; output=%q", out)
	}
	lower := strings.ToLower(err.Error() + out)
	if !strings.Contains(lower, "did you mean") {
		t.Fatalf("expected 'did you mean' for subcommand typo 'lsit'; got err=%q output=%q", err, out)
	}
	if !strings.Contains(lower, "list") {
		t.Fatalf("expected suggestion 'list' for subcommand typo 'lsit'; got err=%q output=%q", err, out)
	}
}
