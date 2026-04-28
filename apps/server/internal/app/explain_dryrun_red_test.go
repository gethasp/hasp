package app

// RED tests for hasp-cgl5: --dry-run implies --explain.
//
// Contract:
//   - 'hasp run --dry-run -- cmd' (no --explain) succeeds and emits an
//     explain payload, because --dry-run silently sets --explain.
//   - '--dry-run' with no command still succeeds (no child needed for dry-run).
//   - '--explain' alone still works (regression guard).

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// TestRunDryRunImpliesExplain verifies that --dry-run alone (without
// --explain) succeeds and emits explain output rather than returning
// "--dry-run requires --explain".
func TestRunDryRunImpliesExplain(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	starter := newDaemonTestStarter(t)
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	args := []string{
		"--project-root", projectRoot,
		"--dry-run",
		"--", "echo", "hi",
	}
	var stdout, stderr bytes.Buffer
	err := runCommand(context.Background(), args, &stdout, &stderr, starter)
	if err != nil {
		t.Fatalf("run --dry-run (no --explain) should succeed; got error: %v\nstderr=%s", err, stderr.String())
	}
	combined := stderr.String() + stdout.String()
	for _, want := range []string{"project_lease", "secret_grant", "redactor"} {
		if !strings.Contains(combined, want) {
			t.Fatalf("expected explain output to contain %q; got:\nstderr=%s\nstdout=%s", want, stderr.String(), stdout.String())
		}
	}
}

// TestRunDryRunWithoutCommandSucceeds verifies that --dry-run with no
// trailing command succeeds (dry-run implies explain; no child needed).
func TestRunDryRunWithoutCommandSucceeds(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	starter := newDaemonTestStarter(t)
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	// --dry-run alone (no -- <command>) must still succeed as a dry run
	// (explain + exit 0) because --dry-run implies --explain and no command
	// is required in dry-run mode.
	args := []string{
		"--project-root", projectRoot,
		"--dry-run",
	}
	var stdout, stderr bytes.Buffer
	err := runCommand(context.Background(), args, &stdout, &stderr, starter)
	if err != nil {
		t.Fatalf("run --dry-run without command should succeed (dry-run needs no command); got error: %v\nstderr=%s", err, stderr.String())
	}
	combined := stderr.String() + stdout.String()
	if !strings.Contains(combined, "project_lease") {
		t.Fatalf("expected explain output even without command; got:\nstderr=%s\nstdout=%s", stderr.String(), stdout.String())
	}
}

// TestRunExplainWithoutDryRunStillWorks is a regression guard: --explain
// alone must continue to work exactly as before.
func TestRunExplainWithoutDryRunStillWorks(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	starter := newDaemonTestStarter(t)
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	// --explain with a command: should succeed and print explain output.
	// The child (true) is expected to execute.
	args := []string{
		"--project-root", projectRoot,
		"--explain",
		"--", "true",
	}
	var stdout, stderr bytes.Buffer
	err := runCommand(context.Background(), args, &stdout, &stderr, starter)
	if err != nil {
		t.Fatalf("run --explain (no --dry-run) should succeed; got error: %v\nstderr=%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String()+stdout.String(), "project_lease") {
		t.Fatalf("expected explain output on stderr; got:\nstderr=%s\nstdout=%s", stderr.String(), stdout.String())
	}
}
