package app

import (
	"bytes"
	"context"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProjectRootNoticeImplicitDefaultPrintsToStderr is the core contract: when
// --project-root is not explicitly passed, the resolved absolute path must be
// announced to stderr so a user running `hasp run` from /tmp doesn't get a
// 'not a git repo' surprise without ever seeing which path was used.
func TestProjectRootNoticeImplicitDefaultPrintsToStderr(t *testing.T) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	pr := fs.String("project-root", ".", "")
	if err := fs.Parse([]string{"--", "echo", "hi"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *pr != "." {
		t.Fatalf("project-root default = %q, want .", *pr)
	}
	var stderr bytes.Buffer
	noteResolvedProjectRootIfImplicit(fs, false, "/tmp/example", &stderr)
	got := stderr.String()
	if !strings.Contains(got, "[hasp] project-root resolved to /tmp/example") {
		t.Fatalf("expected stderr notice, got: %q", got)
	}
}

// TestProjectRootNoticeExplicitFlagSuppressed: if the user typed --project-root
// they already know what they picked — re-printing it would be noise.
func TestProjectRootNoticeExplicitFlagSuppressed(t *testing.T) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	fs.String("project-root", ".", "")
	if err := fs.Parse([]string{"--project-root", "/explicit/path", "--", "echo", "hi"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var stderr bytes.Buffer
	noteResolvedProjectRootIfImplicit(fs, false, "/explicit/path", &stderr)
	if stderr.Len() != 0 {
		t.Fatalf("expected no notice when explicit, got: %q", stderr.String())
	}
}

// TestProjectRootNoticeJSONSuppressed protects machine-readable consumers:
// once --json is set, stderr must stay empty so future strict --json contract
// (hasp-ynci) keeps a clean envelope.
func TestProjectRootNoticeJSONSuppressed(t *testing.T) {
	fs := flag.NewFlagSet("write-env", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	fs.String("project-root", ".", "")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var stderr bytes.Buffer
	noteResolvedProjectRootIfImplicit(fs, true, "/tmp/example", &stderr)
	if stderr.Len() != 0 {
		t.Fatalf("expected JSON to suppress notice, got: %q", stderr.String())
	}
}

// TestProjectRootNoticeNilStderrIsSafe so callers can pass io.Discard or nil
// without a guard at every site.
func TestProjectRootNoticeNilStderrIsSafe(t *testing.T) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	fs.String("project-root", ".", "")
	_ = fs.Parse(nil)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil stderr panicked: %v", r)
		}
	}()
	noteResolvedProjectRootIfImplicit(fs, false, "/tmp/example", nil)
}

// TestProjectRootNoticeFormatStable locks the exact line shape so other tooling
// (and the inevitable doctest in CLAUDE.md) can match against it.
func TestProjectRootNoticeFormatStable(t *testing.T) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	fs.String("project-root", ".", "")
	_ = fs.Parse(nil)
	var stderr bytes.Buffer
	noteResolvedProjectRootIfImplicit(fs, false, "/abs/path", &stderr)
	got := stderr.String()
	want := "[hasp] project-root resolved to /abs/path\n"
	if got != want {
		t.Fatalf("notice = %q, want %q", got, want)
	}
}

// TestCheckRepoEmitsProjectRootNotice covers the wiring inside checkRepoCommand
// — when run with default --project-root, stderr must carry the resolved path.
// Using --json must still suppress it.
func TestCheckRepoEmitsProjectRootNotice(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(projectRoot); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	var stderr bytes.Buffer
	if err := checkRepoCommand(context.Background(), nil, io.Discard, &stderr); err != nil {
		t.Fatalf("check-repo (implicit project-root): %v", err)
	}
	notice := stderr.String()
	wantedFragment := "[hasp] project-root resolved to "
	if !strings.Contains(notice, wantedFragment) {
		t.Fatalf("expected stderr notice with prefix %q, got: %q", wantedFragment, notice)
	}
	resolved, err := filepath.EvalSymlinks(projectRoot)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	if !strings.Contains(notice, resolved) {
		t.Fatalf("notice should mention resolved path %q; got %q", resolved, notice)
	}

	stderr.Reset()
	if err := checkRepoCommand(context.Background(), []string{"--json"}, io.Discard, &stderr); err != nil {
		t.Fatalf("check-repo --json: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected --json to suppress notice, got: %q", stderr.String())
	}
}

// TestCheckRepoExplicitProjectRootSuppressesNotice protects against operator-typed
// paths getting echoed back at them — the user already knows what they passed.
func TestCheckRepoExplicitProjectRootSuppressesNotice(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	var stderr bytes.Buffer
	if err := checkRepoCommand(context.Background(), []string{"--project-root", projectRoot}, io.Discard, &stderr); err != nil {
		t.Fatalf("check-repo (explicit): %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no notice when --project-root explicit, got: %q", stderr.String())
	}
}
