package app

// RED tests for init command grouping.
//
// Contract pinned:
//   - `hasp` (no args) / `hasp help` does NOT list "init" under "Daily commands".
//   - `hasp setup` DOES appear in the daily-command block.
//   - `hasp help init` (and `hasp init --help`) still work — init is not removed,
//     just de-advertised from the primary help surface.

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// TestInitNotInDailyCommandBlock asserts that the root help listing does not
// include "init" inside the "Daily commands" section.
func TestInitNotInDailyCommandBlock(t *testing.T) {
	lockAppSeams(t)
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("hasp (no args): %v", err)
	}
	out := stdout.String()

	dailyStart := strings.Index(out, "Daily commands")
	if dailyStart < 0 {
		t.Fatalf("expected 'Daily commands' section in root help output, got:\n%s", out)
	}

	// Find the end of the Daily commands section (next blank line followed by a
	// non-space character, which signals the next section heading).
	dailySection := out[dailyStart:]
	// The next section heading starts after "Daily commands\n" — find where
	// the Utility commands block begins (or end of string).
	utilityStart := strings.Index(dailySection, "Utility commands")
	if utilityStart >= 0 {
		dailySection = dailySection[:utilityStart]
	}

	if strings.Contains(dailySection, "  init") {
		t.Fatalf("'init' must not appear in the Daily commands block; got:\n%s", dailySection)
	}
}

// TestSetupInDailyCommandBlock asserts that "setup" appears in the daily-command block.
func TestSetupInDailyCommandBlock(t *testing.T) {
	lockAppSeams(t)
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("hasp (no args): %v", err)
	}
	out := stdout.String()

	dailyStart := strings.Index(out, "Daily commands")
	if dailyStart < 0 {
		t.Fatalf("expected 'Daily commands' section in root help output, got:\n%s", out)
	}
	dailySection := out[dailyStart:]
	utilityStart := strings.Index(dailySection, "Utility commands")
	if utilityStart >= 0 {
		dailySection = dailySection[:utilityStart]
	}

	if !strings.Contains(dailySection, "setup") {
		t.Fatalf("'setup' must appear in the Daily commands block; got:\n%s", dailySection)
	}
}

// TestHelpInitTopicStillWorks asserts that `hasp help init` is still registered
// and returns the init help text. The command must remain accessible.
func TestHelpInitTopicStillWorks(t *testing.T) {
	lockAppSeams(t)
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"help", "init"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("hasp help init: %v", err)
	}
	if !strings.Contains(stdout.String(), "Create the local encrypted vault") {
		t.Fatalf("expected init help text, got:\n%s", stdout.String())
	}
}

// TestInitHelpFlagStillWorks asserts that `hasp init --help` still routes to
// init's help topic, proving the command itself is not removed.
func TestInitHelpFlagStillWorks(t *testing.T) {
	lockAppSeams(t)
	starter := &fakeStarter{}
	var stdout bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"init", "--help"}, bytes.NewBuffer(nil), &stdout, io.Discard, starter); err != nil {
		t.Fatalf("hasp init --help: %v", err)
	}
	if !strings.Contains(stdout.String(), "Create the local encrypted vault") {
		t.Fatalf("expected init help text from --help flag, got:\n%s", stdout.String())
	}
}
