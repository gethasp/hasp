package app

// RED tests for hasp-2vdm — top-level global flags. Contract pinned:
//
//   - `hasp --version` prints the build version (same string as `hasp version`).
//   - Global flags parsed before dispatch: --json, --yes, --quiet, --verbose,
//     --debug, --version are recognised when they appear before the subcommand
//     name. They are stripped from args so the subcommand sees a clean slate.
//   - Global flag state is exposed via globalFlagsFromContext(ctx); subcommands
//     opt in. Existing per-subcommand --json/--yes parsing is preserved (mixed
//     placement still works) — the global pre-parse only handles the leading
//     prefix.
//   - Unknown global flags fall through to the subcommand parser (so a
//     subcommand-specific flag placed after the command name is unaffected).
//   - `hasp --version` short-circuits dispatch: no subcommand is required.

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/release"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func TestRunTopLevelVersionFlagPrintsVersion(t *testing.T) {
	lockAppSeams(t)
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"--version"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("--version: %v", err)
	}
	want := runtime.VersionString()
	if !strings.Contains(stdout.String(), want) {
		t.Fatalf("expected %q in stdout, got %q", want, stdout.String())
	}
}

func TestRunTopLevelVersionFlagWithJSONEmitsJSON(t *testing.T) {
	lockAppSeams(t)
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"--json", "--version"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("--json --version: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, `"version"`) || !strings.Contains(out, `"go_version"`) {
		t.Fatalf("expected JSON payload, got %q", out)
	}
}

func TestRunStripsLeadingGlobalFlagsBeforeDispatch(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)
	if err := runWithStarter(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Use --json as a leading global flag before the subcommand. The pre-parse
	// stores the flag in ctx via globalFlagsFromContext; renderers consult it
	// so the subcommand emits a JSON payload even without a local --json flag.
	var stdout bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"--json", "status"}, bytes.NewBuffer(nil), &stdout, io.Discard, starter); err != nil {
		t.Fatalf("--json status: %v", err)
	}
	if !strings.Contains(stdout.String(), `"socket_path"`) {
		t.Fatalf("expected JSON status payload (with socket_path), got %q", stdout.String())
	}
}

func TestGlobalFlagsFromContextDefaultsAreZero(t *testing.T) {
	gf := globalFlagsFromContext(context.Background())
	if gf.json || gf.yes || gf.quiet || gf.verbose || gf.debug {
		t.Fatalf("expected zero-value globalFlags from empty context, got %+v", gf)
	}
}

func TestParseGlobalFlagsExtractsLeadingFlags(t *testing.T) {
	gf, rest, err := parseGlobalFlags([]string{"--json", "--quiet", "--verbose", "--debug", "--yes", "status", "--foo"})
	if err != nil {
		t.Fatalf("parseGlobalFlags: %v", err)
	}
	if !gf.json || !gf.quiet || !gf.verbose || !gf.debug || !gf.yes {
		t.Fatalf("expected all flags set, got %+v", gf)
	}
	want := []string{"status", "--foo"}
	if len(rest) != len(want) || rest[0] != want[0] || rest[1] != want[1] {
		t.Fatalf("expected rest %v, got %v", want, rest)
	}
}

func TestParseGlobalFlagsExtractsGlobalFlagAfterSubcmd(t *testing.T) {
	// After hasp-1vrg fix: global flags positioned after the subcommand name
	// must be extracted from the arg list and merged into gf, NOT left in rest.
	gf, rest, err := parseGlobalFlags([]string{"status", "--json"})
	if err != nil {
		t.Fatalf("parseGlobalFlags: %v", err)
	}
	if !gf.json {
		t.Fatalf("expected gf.json=true (global flag extracted from post-subcommand position), got %+v", gf)
	}
	// rest should contain only the positional subcommand, not the global flag.
	if len(rest) != 1 || rest[0] != "status" {
		t.Fatalf("expected rest=[status], got %v", rest)
	}
}

func TestParseGlobalFlagsLeavesCommandVersionFlagForUpgrade(t *testing.T) {
	gf, rest, err := parseGlobalFlags([]string{"upgrade", "--version", "v1.1.0", "--json", "--yes"})
	if err != nil {
		t.Fatalf("parseGlobalFlags: %v", err)
	}
	if !gf.json || !gf.yes {
		t.Fatalf("expected post-subcommand --json and --yes to remain global, got %+v", gf)
	}
	want := []string{"upgrade", "--version", "v1.1.0"}
	if len(rest) != len(want) {
		t.Fatalf("expected rest %v, got %v", want, rest)
	}
	for i := range want {
		if rest[i] != want[i] {
			t.Fatalf("expected rest %v, got %v", want, rest)
		}
	}
}

func TestRunUpgradeVersionFlagDispatchesToUpgradeCommand(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_VERSION", "1.0.0")
	restore := release.SetPinnedKeysForTest("")
	defer restore()

	var stdout, stderr bytes.Buffer
	err := runWithStarter(context.Background(), []string{"upgrade", "--version", "v1.1.0", "--yes", "--json"}, bytes.NewReader(nil), &stdout, &stderr, &fakeStarter{})
	if err == nil {
		t.Fatal("expected unsigned-build upgrade refusal")
	}
	if stdout.Len() != 0 {
		t.Fatalf("upgrade dispatch should not print version JSON on stdout, got %q", stdout.String())
	}
	if !strings.Contains(err.Error(), "no embedded release-signing keys") {
		t.Fatalf("expected upgrade no-key refusal, got %v", err)
	}
}

func TestParseGlobalFlagsRejectsUnknownDashFlag(t *testing.T) {
	if _, _, err := parseGlobalFlags([]string{"--bogus", "status"}); err == nil {
		t.Fatal("expected error for unknown leading flag")
	}
}

func TestParseGlobalFlagsHandlesEqualsForm(t *testing.T) {
	gf, rest, err := parseGlobalFlags([]string{"--json=true", "--quiet=false", "status"})
	if err != nil {
		t.Fatalf("parseGlobalFlags: %v", err)
	}
	if !gf.json || gf.quiet {
		t.Fatalf("expected json=true quiet=false, got %+v", gf)
	}
	if len(rest) != 1 || rest[0] != "status" {
		t.Fatalf("expected rest [status], got %v", rest)
	}
}

func TestParseGlobalFlagsRecognisesNoColor(t *testing.T) {
	gf, rest, err := parseGlobalFlags([]string{"--no-color", "secret", "list"})
	if err != nil {
		t.Fatalf("parseGlobalFlags: %v", err)
	}
	if !gf.noColor {
		t.Fatalf("expected no-color set, got %+v", gf)
	}
	if len(rest) != 2 || rest[0] != "secret" || rest[1] != "list" {
		t.Fatalf("expected rest [secret list], got %v", rest)
	}
}

// TestParseGlobalFlagsRejectsNoPager confirms --no-pager is rejected since
// no pager seam exists. The flag was removed from parseGlobalFlags in hasp-20mp.
func TestParseGlobalFlagsRejectsNoPager(t *testing.T) {
	_, _, err := parseGlobalFlags([]string{"--no-pager", "secret", "list"})
	if err == nil {
		t.Fatal("expected error for --no-pager (flag removed; no pager seam exists)")
	}
}

func TestParseGlobalFlagsTreatsDoubleDashAsTerminator(t *testing.T) {
	gf, rest, err := parseGlobalFlags([]string{"--json", "--", "status", "--quiet"})
	if err != nil {
		t.Fatalf("parseGlobalFlags: %v", err)
	}
	if !gf.json {
		t.Fatalf("expected json=true, got %+v", gf)
	}
	// "--" itself is preserved so commands that genuinely use it (run/inject) still see it.
	if len(rest) != 3 || rest[0] != "--" || rest[1] != "status" || rest[2] != "--quiet" {
		t.Fatalf("expected rest [-- status --quiet], got %v", rest)
	}
}
