package hooks

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallCreatesManagedHooksAndBacksUpExistingHook(t *testing.T) {
	projectRoot := t.TempDir()
	runGit(t, projectRoot, "init")
	hooksDir := mustHooksDir(t, projectRoot)
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("mkdir hooks dir: %v", err)
	}
	legacyPath := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(legacyPath, []byte("#!/usr/bin/env bash\necho legacy\n"), 0o755); err != nil {
		t.Fatalf("write legacy hook: %v", err)
	}

	if err := Install(projectRoot); err != nil {
		t.Fatalf("install hooks: %v", err)
	}

	managed, err := os.ReadFile(legacyPath)
	if err != nil {
		t.Fatalf("read managed hook: %v", err)
	}
	if !strings.Contains(string(managed), marker) {
		t.Fatalf("missing managed marker: %s", string(managed))
	}
	backup, err := os.ReadFile(legacyPath + ".pre-hasp")
	if err != nil {
		t.Fatalf("read backup hook: %v", err)
	}
	if !strings.Contains(string(backup), "legacy") {
		t.Fatalf("unexpected backup content: %s", string(backup))
	}

	prePush, err := os.ReadFile(filepath.Join(hooksDir, "pre-push"))
	if err != nil {
		t.Fatalf("read pre-push hook: %v", err)
	}
	if !strings.Contains(string(prePush), marker) {
		t.Fatalf("missing pre-push marker: %s", string(prePush))
	}
	// pre-commit scans the staged index (hasp-8buu); pre-push keeps the
	// working-tree scan until committed-range scanning lands.
	if !strings.Contains(string(managed), "--staged") {
		t.Fatalf("pre-commit hook should pass --staged: %s", string(managed))
	}
	if strings.Contains(string(prePush), "--staged") {
		t.Fatalf("pre-push hook should not pass --staged yet: %s", string(prePush))
	}
	if !ManagedHooksPresent(projectRoot) {
		t.Fatal("expected managed hooks to be present")
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v: %s", args, err, string(out))
	}
}

func mustHooksDir(t *testing.T, projectRoot string) string {
	t.Helper()
	plan, err := ResolveInstallPlan(projectRoot)
	if err != nil {
		t.Fatalf("resolve hooks dir: %v", err)
	}
	return plan.HooksDir
}

// TestInstallHookDoesNotShellInjectProjectRoot guards against command
// substitution in the generated hook (hasp-g84c). A project path containing
// $(...) must be embedded as an inert single-quoted literal, not executed when
// git runs the hook.
func TestInstallHookResolvesProjectRootAtRuntimeWithoutEmbeddedPath(t *testing.T) {
	dir := t.TempDir()
	hookPath := filepath.Join(dir, "pre-commit")
	malicious := "/repo$(touch INJECTED)"

	if err := installHook(hookPath, true); err != nil {
		t.Fatalf("installHook: %v", err)
	}

	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read hook: %v", err)
	}
	if strings.Contains(string(content), malicious) {
		t.Fatalf("hook should not embed install-time project root:\n%s", string(content))
	}
	if !strings.Contains(string(content), "rev-parse --show-toplevel") {
		t.Fatalf("hook should resolve active project root at runtime:\n%s", string(content))
	}

	// Execute the hook; the embedded $(touch INJECTED) must NOT run. hasp is not
	// on PATH so the hook exits non-zero — that is expected and ignored.
	cmd := exec.Command("bash", hookPath)
	cmd.Dir = dir
	_ = cmd.Run()
	if _, err := os.Stat(filepath.Join(dir, "INJECTED")); err == nil {
		t.Fatal("shell injection: $(touch INJECTED) executed from the hook")
	}
}

func TestInstallFromLinkedWorktreeUsesCommonHooksDirAndRuntimeRoot(t *testing.T) {
	parent := t.TempDir()
	mainRoot := filepath.Join(parent, "main")
	worktreeRoot := filepath.Join(parent, "wt")
	runGit(t, parent, "init", mainRoot)
	runGit(t, mainRoot, "config", "user.email", "test@example.com")
	runGit(t, mainRoot, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(mainRoot, "README.md"), []byte("x\n"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	runGit(t, mainRoot, "add", "README.md")
	runGit(t, mainRoot, "commit", "-m", "init")
	runGit(t, mainRoot, "worktree", "add", worktreeRoot)

	if err := Install(worktreeRoot); err != nil {
		t.Fatalf("install from worktree: %v", err)
	}
	plan := mustPlan(t, worktreeRoot)
	if strings.HasPrefix(plan.HooksDir, worktreeRoot+string(filepath.Separator)) {
		t.Fatalf("hooks dir should be common git dir, got %s", plan.HooksDir)
	}
	if !ManagedHooksPresent(worktreeRoot) {
		t.Fatal("expected managed hooks in linked worktree")
	}

	haspDir := filepath.Join(parent, "bin")
	if err := os.MkdirAll(haspDir, 0o755); err != nil {
		t.Fatalf("mkdir fake hasp dir: %v", err)
	}
	logPath := filepath.Join(parent, "hook-root.log")
	fakeHasp := filepath.Join(haspDir, "hasp")
	if err := os.WriteFile(fakeHasp, []byte("#!/usr/bin/env bash\nprintf '%s\\n' \"$3\" > "+shellSingleQuote(logPath)+"\n"), 0o755); err != nil {
		t.Fatalf("write fake hasp: %v", err)
	}
	if err := os.WriteFile(filepath.Join(worktreeRoot, "file.txt"), []byte("y\n"), 0o600); err != nil {
		t.Fatalf("write worktree file: %v", err)
	}
	cmd := exec.Command("git", "-C", worktreeRoot, "add", "file.txt")
	cmd.Env = append(os.Environ(), "PATH="+haspDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add in worktree: %v: %s", err, string(out))
	}
	cmd = exec.Command("git", "-C", worktreeRoot, "commit", "-m", "worktree")
	cmd.Env = append(os.Environ(), "PATH="+haspDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit in worktree: %v: %s", err, string(out))
	}
	got, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read hook root log: %v", err)
	}
	gotRoot := canonicalTestPath(t, strings.TrimSpace(string(got)))
	wantRoot := canonicalTestPath(t, worktreeRoot)
	if gotRoot != wantRoot {
		t.Fatalf("hook scanned root %q, want %q", gotRoot, wantRoot)
	}
}

func TestInstallHonorsSafeRelativeCoreHooksPath(t *testing.T) {
	projectRoot := t.TempDir()
	runGit(t, projectRoot, "init")
	runGit(t, projectRoot, "config", "core.hooksPath", ".githooks")

	if err := Install(projectRoot); err != nil {
		t.Fatalf("install with relative hooksPath: %v", err)
	}
	if _, err := os.Stat(filepath.Join(projectRoot, ".githooks", "pre-commit")); err != nil {
		t.Fatalf("expected managed hook in custom hooksPath: %v", err)
	}
	if !ManagedHooksPresent(projectRoot) {
		t.Fatal("expected managed hooks to be detected through custom hooksPath")
	}
}

func TestInstallRejectsDisabledAndUnsafeCoreHooksPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want error
	}{
		{name: "disabled", path: "/dev/null", want: ErrHooksDisabled},
		{name: "empty", path: "", want: ErrHooksDisabled},
		{name: "outside", path: filepath.Join(t.TempDir(), "global-hooks"), want: ErrUnsafeHooksDir},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projectRoot := t.TempDir()
			runGit(t, projectRoot, "init")
			runGit(t, projectRoot, "config", "core.hooksPath", tt.path)
			err := Install(projectRoot)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Install error = %v, want %v", err, tt.want)
			}
			if ManagedHooksPresent(projectRoot) {
				t.Fatal("disabled/unsafe hooks path must not report managed hooks present")
			}
		})
	}
}

func TestInstallRejectsCoreHooksPathSymlinkEscape(t *testing.T) {
	projectRoot := t.TempDir()
	runGit(t, projectRoot, "init")
	outside := t.TempDir()
	linkPath := filepath.Join(projectRoot, ".githooks")
	if err := os.Symlink(outside, linkPath); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	runGit(t, projectRoot, "config", "core.hooksPath", ".githooks")

	err := Install(projectRoot)
	if !errors.Is(err, ErrUnsafeHooksDir) {
		t.Fatalf("Install error = %v, want %v", err, ErrUnsafeHooksDir)
	}
	if _, err := os.Stat(filepath.Join(outside, "pre-commit")); !os.IsNotExist(err) {
		t.Fatalf("must not write hooks through escaped symlink, err=%v", err)
	}
}

func TestInstallRejectsCoreHooksPathSymlinkParentEscape(t *testing.T) {
	projectRoot := t.TempDir()
	runGit(t, projectRoot, "init")
	outside := t.TempDir()
	linkPath := filepath.Join(projectRoot, ".config")
	if err := os.Symlink(outside, linkPath); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	runGit(t, projectRoot, "config", "core.hooksPath", ".config/hooks")

	err := Install(projectRoot)
	if !errors.Is(err, ErrUnsafeHooksDir) {
		t.Fatalf("Install error = %v, want %v", err, ErrUnsafeHooksDir)
	}
	if _, err := os.Stat(filepath.Join(outside, "hooks", "pre-commit")); !os.IsNotExist(err) {
		t.Fatalf("must not write hooks through escaped symlink parent, err=%v", err)
	}
}

func TestInstallRejectsGlobalCoreHooksPathOutsideProject(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()
	runGit(t, projectRoot, "init")
	cmd := exec.Command("git", "config", "--file", filepath.Join(home, ".gitconfig"), "core.hooksPath", filepath.Join(t.TempDir(), "global-hooks"))
	cmd.Env = append(os.Environ(), "HOME="+home)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git config global hooksPath: %v: %s", err, string(out))
	}
	err := Install(projectRoot)
	if !errors.Is(err, ErrUnsafeHooksDir) {
		t.Fatalf("Install error = %v, want %v", err, ErrUnsafeHooksDir)
	}
}

func TestInstallHonorsWorktreeSpecificCoreHooksPath(t *testing.T) {
	parent := t.TempDir()
	mainRoot := filepath.Join(parent, "main")
	worktreeRoot := filepath.Join(parent, "wt")
	runGit(t, parent, "init", mainRoot)
	runGit(t, mainRoot, "config", "user.email", "test@example.com")
	runGit(t, mainRoot, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(mainRoot, "README.md"), []byte("x\n"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	runGit(t, mainRoot, "add", "README.md")
	runGit(t, mainRoot, "commit", "-m", "init")
	runGit(t, mainRoot, "config", "extensions.worktreeConfig", "true")
	runGit(t, mainRoot, "worktree", "add", worktreeRoot)
	runGit(t, worktreeRoot, "config", "--worktree", "core.hooksPath", ".wt-hooks")

	if err := Install(worktreeRoot); err != nil {
		t.Fatalf("install with worktree hooksPath: %v", err)
	}
	if _, err := os.Stat(filepath.Join(worktreeRoot, ".wt-hooks", "pre-commit")); err != nil {
		t.Fatalf("expected worktree-specific hook: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mainRoot, ".git", "hooks", "pre-commit")); !os.IsNotExist(err) {
		t.Fatalf("default common hook should not be installed when worktree hooksPath is set, err=%v", err)
	}
}

func TestManagedHooksPresentRequiresHASPMarker(t *testing.T) {
	projectRoot := t.TempDir()
	runGit(t, projectRoot, "init")
	hooksDir := mustHooksDir(t, projectRoot)
	if err := os.WriteFile(filepath.Join(hooksDir, "pre-commit"), []byte("#!/bin/sh\necho other\n"), 0o755); err != nil {
		t.Fatalf("write foreign hook: %v", err)
	}
	if ManagedHooksPresent(projectRoot) {
		t.Fatal("foreign hook must not count as managed")
	}
}

func mustPlan(t *testing.T, projectRoot string) InstallPlan {
	t.Helper()
	plan, err := ResolveInstallPlan(projectRoot)
	if err != nil {
		t.Fatalf("resolve install plan: %v", err)
	}
	return plan
}

func canonicalTestPath(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve test path %q: %v", path, err)
	}
	return resolved
}
