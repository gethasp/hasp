package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// hasp-khcj: confirm the standalone rewrite handles the canonical
// "flag provided but not defined: -bad-flag" form Go emits even when the
// user typed `--bad-flag`.
func TestRewriteFlagDashFormStringRewritesLongNames(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"unknown long flag", "flag provided but not defined: -bad-flag", "flag provided but not defined: --bad-flag"},
		{"missing argument", "flag needs an argument: -project-root", "flag needs an argument: --project-root"},
		{"keep short flag", "flag provided but not defined: -n", "flag provided but not defined: -n"},
		{"keep short -f", "flag provided but not defined: -f", "flag provided but not defined: -f"},
		{"already double-dash", "flag provided but not defined: --already", "flag provided but not defined: --already"},
		{"underscored name", "flag provided but not defined: -dry_run", "flag provided but not defined: --dry_run"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rewriteFlagDashFormString(tc.in); got != tc.want {
				t.Fatalf("rewriteFlagDashFormString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// rewriteFlagDashForm passes nil through and preserves errors that don't
// reference a long-form dash flag.
func TestRewriteFlagDashFormIdentityForNonFlagErrors(t *testing.T) {
	if err := rewriteFlagDashForm(nil); err != nil {
		t.Fatalf("rewriteFlagDashForm(nil): expected nil, got %v", err)
	}
	original := errors.New("vault is locked; run `hasp init` first")
	got := rewriteFlagDashForm(original)
	if got != original {
		t.Fatalf("rewriteFlagDashForm should return the same error for unrelated messages, got %v", got)
	}
}

// End-to-end: passing `--bad-flag` to `hasp run` should produce a message
// that echoes `--bad-flag`, not `-bad-flag`.
func TestRunBadFlagErrorEchoesDoubleDashForm(t *testing.T) {
	lockAppSeams(t)

	var stdout, stderr bytes.Buffer
	err := runWithStarter(context.Background(), []string{"run", "--bad-flag", "--", "true"}, bytes.NewBuffer(nil), &stdout, &stderr, &fakeStarter{err: io.EOF})
	if err == nil {
		t.Fatal("expected error from `hasp run --bad-flag`")
	}
	msg := err.Error()
	if !strings.Contains(msg, "--bad-flag") {
		t.Fatalf("expected error to echo --bad-flag, got %q", msg)
	}
	if strings.Contains(msg, " -bad-flag") {
		t.Fatalf("error still echoes single-dash form: %q", msg)
	}
}
