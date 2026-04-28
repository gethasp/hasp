package app

// RED tests for hasp-1vrg — global flags positioned AFTER the subcommand.
//
// These tests assert the behaviour that SHOULD exist but currently does not:
// `hasp doctor --json --no-color` must not return "flag provided but not
// defined: -no-color" when --no-color appears after the subcommand name.
//
// Currently parseGlobalFlags stops at the first non-flag token (the subcommand
// name) and hands the remaining args to the subcommand's own FlagSet.  The
// subcommand FlagSets do not declare global flags like --no-color, so they
// produce an error. The fix (not part of this file) must strip/handle global
// flags wherever they appear in the arg list.

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

// mustInitVault is a helper that initialises a vault in a temp home dir and
// returns the starter that was used.  It calls t.Fatal on any error.
func mustInitVaultForPostSub(t *testing.T) starter {
	t.Helper()
	homeDir := t.TempDir()
	t.Setenv(paths.EnvHome, homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)
	if err := runWithStarter(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter); err != nil {
		t.Fatalf("init: %v", err)
	}
	return starter
}

// TestGlobalFlagsPostSub_DoctorJsonNoColor is the primary regression from the
// bead description: `hasp doctor --json --no-color` must NOT return
// "flag provided but not defined: -no-color".
func TestGlobalFlagsPostSub_DoctorJsonNoColor(t *testing.T) {
	starter := mustInitVaultForPostSub(t)

	var stdout, stderr bytes.Buffer
	err := runWithStarter(
		context.Background(),
		[]string{"doctor", "--json", "--no-color"},
		bytes.NewBuffer(nil), &stdout, &stderr, starter,
	)
	if err != nil {
		if strings.Contains(err.Error(), "flag provided but not defined") {
			t.Fatalf("global flag --no-color after subcommand caused 'flag provided but not defined': %v", err)
		}
		// Any other error (e.g. daemon not running) is acceptable for this test,
		// because the contract is only that the flag is not rejected.
		// However for full signal we log it:
		t.Logf("doctor --json --no-color returned non-flag error (acceptable): %v", err)
	}
}

// TestGlobalFlagsPostSub_SecretListNoColor checks that --no-color after
// `secret list` does not produce "flag provided but not defined".
func TestGlobalFlagsPostSub_SecretListNoColor(t *testing.T) {
	starter := mustInitVaultForPostSub(t)

	var stdout, stderr bytes.Buffer
	err := runWithStarter(
		context.Background(),
		[]string{"secret", "list", "--no-color"},
		bytes.NewBuffer(nil), &stdout, &stderr, starter,
	)
	if err != nil && strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("global flag --no-color after 'secret list' caused 'flag provided but not defined': %v", err)
	}
}

// TestGlobalFlagsPostSub_VersionJson checks that --json after `version` does
// not produce "flag provided but not defined" (version already declares --json
// locally, but this test is a sanity-check that post-sub global flags survive).
func TestGlobalFlagsPostSub_VersionJson(t *testing.T) {
	t.Setenv(paths.EnvHome, t.TempDir())

	var stdout, stderr bytes.Buffer
	err := Run(
		context.Background(),
		[]string{"version", "--json"},
		bytes.NewBuffer(nil), &stdout, &stderr,
	)
	if err != nil {
		t.Fatalf("version --json: %v", err)
	}
	if !strings.Contains(stdout.String(), `"version"`) {
		t.Fatalf("expected JSON output from version --json, got: %q", stdout.String())
	}
}

// TestGlobalFlagsPostSub_DoctorNoColor confirms --no-color alone after
// `doctor` (without --json) is also accepted.
func TestGlobalFlagsPostSub_DoctorNoColor(t *testing.T) {
	starter := mustInitVaultForPostSub(t)

	var stdout, stderr bytes.Buffer
	err := runWithStarter(
		context.Background(),
		[]string{"doctor", "--no-color"},
		bytes.NewBuffer(nil), &stdout, &stderr, starter,
	)
	if err != nil && strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("global flag --no-color after 'doctor' caused 'flag provided but not defined': %v", err)
	}
}

// TestGlobalFlagsPostSub_GlobalFlagsBeforeSubcmdStillWork is a regression
// guard: placing global flags BEFORE the subcommand must continue to work.
func TestGlobalFlagsPostSub_GlobalFlagsBeforeSubcmdStillWork(t *testing.T) {
	starter := mustInitVaultForPostSub(t)

	var stdout bytes.Buffer
	err := runWithStarter(
		context.Background(),
		[]string{"--no-color", "secret", "list"},
		bytes.NewBuffer(nil), &stdout, io.Discard, starter,
	)
	if err != nil {
		t.Fatalf("--no-color before subcommand failed: %v", err)
	}
}

// TestGlobalFlagsPostSub_JsonBeforeSubcmdStillWorks checks that --json before
// the subcommand still routes through correctly (regression).
func TestGlobalFlagsPostSub_JsonBeforeSubcmdStillWorks(t *testing.T) {
	starter := mustInitVaultForPostSub(t)

	var stdout bytes.Buffer
	err := runWithStarter(
		context.Background(),
		[]string{"--json", "secret", "list"},
		bytes.NewBuffer(nil), &stdout, io.Discard, starter,
	)
	if err != nil {
		t.Fatalf("--json before 'secret list' failed: %v", err)
	}
	if !strings.Contains(stdout.String(), `"secrets"`) {
		t.Fatalf("expected JSON with 'secrets' key, got: %q", stdout.String())
	}
}

// TestGlobalFlagsPostSub_UnknownFlagAfterSubcmdStillErrors verifies that a
// genuinely unknown flag after a subcommand still produces an error. This
// ensures the fix does not open a hole where every random flag is silently
// swallowed.
func TestGlobalFlagsPostSub_UnknownFlagAfterSubcmdStillErrors(t *testing.T) {
	starter := mustInitVaultForPostSub(t)

	var stdout, stderr bytes.Buffer
	err := runWithStarter(
		context.Background(),
		[]string{"doctor", "--definitely-not-a-real-flag-xyz"},
		bytes.NewBuffer(nil), &stdout, &stderr, starter,
	)
	if err == nil {
		t.Fatal("expected error for unknown flag --definitely-not-a-real-flag-xyz after doctor, got nil")
	}
}

// TestGlobalFlagsPostSub_CtxHasNoColorTrue verifies that when --no-color
// appears after the subcommand name, the globalFlags extracted by parsing
// have noColor=true. This tests the intended contract at the parsing level
// by simulating the arg rewriting that the fix must implement: global flags
// must be stripped from the post-subcommand tail and merged into gf.
//
// Currently parseGlobalFlags stops at the first non-flag token and will NOT
// see --no-color when it appears after "doctor". The test calls a hypothetical
// parseGlobalFlagsFromAll (or the fixed parseGlobalFlags) to confirm the
// post-fix invariant. Until the fix exists this test verifies the BUG: the
// current parser leaves --no-color in rest rather than merging it into gf.
func TestGlobalFlagsPostSub_CurrentParserLeavesGlobalFlagInRest(t *testing.T) {
	// After the fix this test must be updated or removed: the repaired parser
	// must NOT leave --no-color in rest when it is a recognised global flag.
	// For now we assert the current (broken) behaviour to make the test RED in
	// the expected direction: --no-color should NOT appear in rest.
	gf, rest, err := parseGlobalFlags([]string{"doctor", "--json", "--no-color"})
	if err != nil {
		t.Fatalf("parseGlobalFlags: unexpected error: %v", err)
	}
	// The parser stopped at "doctor" so gf.json and gf.noColor are both false.
	// After the fix they should be true. Assert the desired post-fix state:
	if !gf.json {
		t.Errorf("expected gf.json=true after fix, got false (bug: --json after subcommand not parsed)")
	}
	if !gf.noColor {
		t.Errorf("expected gf.noColor=true after fix, got false (bug: --no-color after subcommand not parsed)")
	}
	// After the fix, rest should contain only ["doctor"] with the global flags stripped.
	if len(rest) != 1 || rest[0] != "doctor" {
		t.Errorf("expected rest=[doctor] after global flags stripped, got %v", rest)
	}
}
