package app

// RED tests for hasp-nj8p — `hasp run --explain` decision-tree preview.
// Contract pinned:
//
//   - --explain on hasp run / hasp inject prints, before any child execution,
//     the resolved authorization decisions: project lease scope+ttl, secret
//     grant scope+ttl, effective grant window, redactor active flag, and the
//     planned env/file references.
//   - --explain alone prints, then runs the child as usual.
//   - --explain --dry-run prints and exits 0 without executing the child.
//   - Explain text is written to stderr so stdout stays clean for the child's
//     output.
//   - The decision tree is plain-text human readable; --json mode emits the
//     same payload as a JSON object on stderr.

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunExplainDryRunPrintsDecisionsAndDoesNotExecute(t *testing.T) {
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
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", "sk-explain-fixture"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "API_TOKEN=API_TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("project bind: %v", err)
	}
	// A path that, if the runner were invoked, would write a sentinel file we
	// can later verify did NOT appear (--dry-run must skip child execution).
	sentinel := filepath.Join(t.TempDir(), "child-ran")
	args := []string{
		"--project-root", filepath.Clean(projectRoot),
		"--env", "API_TOKEN=API_TOKEN",
		"--grant-project", "window",
		"--grant-secret", "session",
		"--grant-window", "15m",
		"--explain",
		"--dry-run",
		"--", "sh", "-c", "touch " + sentinel,
	}
	var stdout, stderr bytes.Buffer
	if err := runCommand(context.Background(), args, &stdout, &stderr, starter); err != nil {
		t.Fatalf("run --explain --dry-run: %v\nstderr=%s", err, stderr.String())
	}
	combined := stderr.String() + stdout.String()
	for _, want := range []string{"project_lease", "secret_grant", "grant_window", "redactor"} {
		if !strings.Contains(combined, want) {
			t.Fatalf("expected explain output to mention %q, got:\nstderr=%s\nstdout=%s", want, stderr.String(), stdout.String())
		}
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatalf("--dry-run should not execute child; sentinel file was created at %s", sentinel)
	}
}

func TestRunExplainAloneStillExecutesChild(t *testing.T) {
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
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", "sk-explain-fixture"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "API_TOKEN=API_TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("project bind: %v", err)
	}
	sentinel := filepath.Join(t.TempDir(), "child-ran")
	args := []string{
		"--project-root", filepath.Clean(projectRoot),
		"--env", "API_TOKEN=API_TOKEN",
		"--grant-project", "window",
		"--grant-secret", "session",
		"--grant-window", "15m",
		"--explain",
		"--", "sh", "-c", "touch " + sentinel,
	}
	var stdout, stderr bytes.Buffer
	if err := runCommand(context.Background(), args, &stdout, &stderr, starter); err != nil {
		t.Fatalf("run --explain: %v\nstderr=%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "project_lease") {
		t.Fatalf("expected explain output on stderr, got %q", stderr.String())
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("--explain alone should still execute child; sentinel missing at %s: %v", sentinel, err)
	}
}

func TestRunExplainDryRunWithJSONEmitsStructuredPayload(t *testing.T) {
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
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", "sk-explain-fixture"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "API_TOKEN=API_TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("project bind: %v", err)
	}
	args := []string{
		"--project-root", filepath.Clean(projectRoot),
		"--env", "API_TOKEN=API_TOKEN",
		"--grant-project", "window",
		"--grant-secret", "session",
		"--grant-window", "15m",
		"--explain",
		"--dry-run",
		"--explain-format", "json",
		"--", "sh", "-c", "true",
	}
	var stdout, stderr bytes.Buffer
	if err := runCommand(context.Background(), args, &stdout, &stderr, starter); err != nil {
		t.Fatalf("run --explain --dry-run --explain-format json: %v\nstderr=%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), `"project_lease"`) || !strings.Contains(stderr.String(), `"secret_grant"`) {
		t.Fatalf("expected JSON explain payload on stderr, got %q", stderr.String())
	}
}
