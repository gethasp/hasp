package app

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

// initHaspForBindTest initialises a fresh vault in the given home dir and
// returns the home dir so tests can set HASP_HOME before calling Run.
func initHaspForBindTest(t *testing.T) {
	t.Helper()
	homeDir := t.TempDir()
	t.Setenv(paths.EnvHome, homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
}

// runBind is a small helper that calls "project bind" and returns stdout +
// the error so individual test cases can assert on both.
func runBind(args ...string) (string, error) {
	var out bytes.Buffer
	cmdArgs := append([]string{"project", "bind"}, args...)
	err := Run(context.Background(), cmdArgs, bytes.NewBuffer(nil), &out, io.Discard)
	return out.String(), err
}

// TestProjectBindValidationNonExistentPath checks that binding a path that
// does not exist is rejected and the error mentions "does not exist".
func TestProjectBindValidationNonExistentPath(t *testing.T) {
	lockAppSeams(t)
	initHaspForBindTest(t)

	_, err := runBind("--project-root", "/tmp/surely_this_path_does_not_exist_hasp_test_12345")
	if err == nil {
		t.Fatal("expected error for non-existent path, got nil")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected error to mention 'does not exist', got: %v", err)
	}
}

// TestProjectBindValidationRegularFile checks that passing a regular file as
// --project-root is rejected and the error mentions "not a directory".
func TestProjectBindValidationRegularFile(t *testing.T) {
	lockAppSeams(t)
	initHaspForBindTest(t)

	f, err := os.CreateTemp("", "hasp-bind-file-test-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	filePath := f.Name()
	f.Close()
	t.Cleanup(func() { os.Remove(filePath) })

	_, bindErr := runBind("--project-root", filePath)
	if bindErr == nil {
		t.Fatal("expected error for file path, got nil")
	}
	if !strings.Contains(bindErr.Error(), "not a directory") {
		t.Fatalf("expected error to mention 'not a directory', got: %v", bindErr)
	}
}

// TestProjectBindValidationDirWithoutGit checks that binding a plain directory
// (no .git) is rejected and the error mentions "not a git repository" and
// "--allow-non-git".
func TestProjectBindValidationDirWithoutGit(t *testing.T) {
	lockAppSeams(t)
	initHaspForBindTest(t)

	plainDir := t.TempDir()

	_, err := runBind("--project-root", plainDir)
	if err == nil {
		t.Fatal("expected error for non-git directory, got nil")
	}
	if !strings.Contains(err.Error(), "not a git repository") {
		t.Fatalf("expected error to mention 'not a git repository', got: %v", err)
	}
	if !strings.Contains(err.Error(), "--allow-non-git") {
		t.Fatalf("expected error to mention '--allow-non-git', got: %v", err)
	}
}

// TestProjectBindValidationAllowNonGit checks that --allow-non-git bypasses
// the git-repository requirement and the bind succeeds for a plain directory.
func TestProjectBindValidationAllowNonGit(t *testing.T) {
	lockAppSeams(t)
	initHaspForBindTest(t)

	plainDir := t.TempDir()

	out, err := runBind("--json", "--project-root", plainDir, "--allow-non-git")
	if err != nil {
		t.Fatalf("expected success with --allow-non-git, got: %v", err)
	}
	if !strings.Contains(out, `"hook_installed":false`) {
		t.Fatalf("non-git bind must not report hooks installed, got: %s", out)
	}
}

// TestProjectBindValidationGitDirSuccess checks that binding an existing git
// repository succeeds and the output reports "Hooks installed: yes" when hooks
// actually install without error.
func TestProjectBindValidationGitDirSuccess(t *testing.T) {
	lockAppSeams(t)

	origInstallHooks := installHooksFn
	defer func() { installHooksFn = origInstallHooks }()
	// Stub hook install to succeed without touching the filesystem.
	installHooksFn = func(string) error { return nil }

	initHaspForBindTest(t)

	gitDir := t.TempDir()
	if out, err := initTestGitRepo(gitDir); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	out, err := runBind("--project-root", gitDir, "--hooks=true")
	if err != nil {
		t.Fatalf("expected success for git directory, got: %v", err)
	}
	if !strings.Contains(out, "yes") {
		t.Fatalf("expected output to contain 'yes' for hooks installed, got: %s", out)
	}
}

// TestProjectBindValidationHookInstallError checks that a hook-install failure
// surfaces as an error rather than being silently swallowed.
func TestProjectBindValidationHookInstallError(t *testing.T) {
	lockAppSeams(t)

	origInstallHooks := installHooksFn
	defer func() { installHooksFn = origInstallHooks }()
	installHooksFn = func(string) error {
		return &hookInstallError{msg: "hook install failed: permission denied"}
	}

	initHaspForBindTest(t)

	gitDir := t.TempDir()
	if out, err := initTestGitRepo(gitDir); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	_, err := runBind("--project-root", gitDir, "--hooks=true")
	if err == nil {
		t.Fatal("expected error when hook install fails, got nil")
	}
	if !strings.Contains(err.Error(), "hook install failed") {
		t.Fatalf("expected hook install error to propagate, got: %v", err)
	}
}

// hookInstallError is a simple error type used in tests to simulate a hook
// install failure.
type hookInstallError struct{ msg string }

func (e *hookInstallError) Error() string { return e.msg }
