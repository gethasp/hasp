package hooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallFailsOutsideGitRepo(t *testing.T) {
	if err := Install(t.TempDir()); !errors.Is(err, ErrNotGitRepo) {
		t.Fatalf("expected non-git install failure, got %v", err)
	}
}

func TestInstallHookWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "pre-commit")
	if err := installHook(path, true); err == nil {
		t.Fatal("expected installHook write failure")
	}
}

func TestInstallFailsWhenHooksPathIsAFile(t *testing.T) {
	projectRoot := t.TempDir()
	runGit(t, projectRoot, "init")
	hooksDir := filepath.Join(projectRoot, ".git", "hooks")
	if err := os.RemoveAll(hooksDir); err != nil {
		t.Fatalf("remove hooks dir: %v", err)
	}
	if err := os.WriteFile(hooksDir, []byte("not-a-dir"), 0o600); err != nil {
		t.Fatalf("write hooks file: %v", err)
	}
	if err := Install(projectRoot); err == nil {
		t.Fatal("expected hooks path mkdir failure")
	}
}

func TestInstallFailsWhenMkdirFails(t *testing.T) {
	projectRoot := t.TempDir()
	runGit(t, projectRoot, "init")
	origMkdir := hooksMkdirAll
	defer func() { hooksMkdirAll = origMkdir }()
	hooksMkdirAll = func(string, os.FileMode) error { return fmt.Errorf("mkdir fail") }
	if err := Install(projectRoot); err == nil {
		t.Fatal("expected mkdir failure")
	}
}

func TestInstallHookBackupFailureAndInstallPropagation(t *testing.T) {
	projectRoot := t.TempDir()
	runGit(t, projectRoot, "init")
	hookPath := filepath.Join(mustHooksDir(t, projectRoot), "pre-commit")
	if err := os.WriteFile(hookPath, []byte("#!/usr/bin/env bash\necho legacy\n"), 0o755); err != nil {
		t.Fatalf("write legacy hook: %v", err)
	}
	if err := os.Mkdir(hookPath+".pre-hasp", 0o755); err != nil {
		t.Fatalf("mkdir backup path: %v", err)
	}
	if err := installHook(hookPath, true); err == nil {
		t.Fatal("expected backup failure")
	}
	if err := Install(projectRoot); err == nil {
		t.Fatal("expected install failure to propagate")
	}
}

func TestInstallRefusesSymlinkHook(t *testing.T) {
	projectRoot := t.TempDir()
	runGit(t, projectRoot, "init")
	hookPath := filepath.Join(mustHooksDir(t, projectRoot), "pre-commit")
	target := filepath.Join(t.TempDir(), "outside-hook")
	if err := os.Symlink(target, hookPath); err != nil {
		t.Fatalf("symlink hook: %v", err)
	}
	if err := Install(projectRoot); err == nil {
		t.Fatal("expected symlink hook refusal")
	}
}

func TestResolveInstallPlanPropagatesGitSafeFailures(t *testing.T) {
	projectRoot := t.TempDir()
	runGit(t, projectRoot, "init")
	origCommonDir := hooksCommonDir
	origCoreHooksPath := hooksCoreHooksPath
	t.Cleanup(func() {
		hooksCommonDir = origCommonDir
		hooksCoreHooksPath = origCoreHooksPath
	})

	hooksCommonDir = func(context.Context, string) (string, error) {
		return "", errors.New("common dir failed")
	}
	if _, err := ResolveInstallPlan(projectRoot); err == nil || !strings.Contains(err.Error(), "common dir failed") {
		t.Fatalf("expected common dir failure, got %v", err)
	}

	hooksCommonDir = origCommonDir
	hooksCoreHooksPath = func(context.Context, string) (string, bool, error) {
		return "", false, errors.New("hooks path failed")
	}
	if _, err := ResolveInstallPlan(projectRoot); err == nil || !strings.Contains(err.Error(), "hooks path failed") {
		t.Fatalf("expected hooks path failure, got %v", err)
	}
}

func TestResolveCustomHooksDirCanonicalizationFailures(t *testing.T) {
	root := t.TempDir()
	common := filepath.Join(root, ".git")
	if err := os.MkdirAll(common, 0o755); err != nil {
		t.Fatalf("mkdir common dir: %v", err)
	}

	loop := filepath.Join(root, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := resolveCustomHooksDir(root, common, loop); err == nil || !strings.Contains(err.Error(), "resolve hooks path") {
		t.Fatalf("expected hooks path canonicalization failure, got %v", err)
	}
	if _, err := resolveCustomHooksDir(loop, common, filepath.Join(root, "hooks")); err == nil || !strings.Contains(err.Error(), "resolve project root") {
		t.Fatalf("expected project root canonicalization failure, got %v", err)
	}
	if _, err := resolveCustomHooksDir(root, loop, filepath.Join(root, "hooks")); err == nil || !strings.Contains(err.Error(), "resolve git common dir") {
		t.Fatalf("expected common dir canonicalization failure, got %v", err)
	}
}

func TestCanonicalBoundaryPathSeamedFailureBranches(t *testing.T) {
	origAbs := hooksAbs
	origEval := hooksEvalSymlinks
	t.Cleanup(func() {
		hooksAbs = origAbs
		hooksEvalSymlinks = origEval
	})

	hooksAbs = func(string) (string, error) { return "", errors.New("abs failed") }
	if _, err := canonicalBoundaryPath("relative"); err == nil || !strings.Contains(err.Error(), "abs failed") {
		t.Fatalf("expected abs failure, got %v", err)
	}

	hooksAbs = func(string) (string, error) { return string(filepath.Separator), nil }
	hooksEvalSymlinks = func(string) (string, error) { return "", os.ErrNotExist }
	if _, err := canonicalBoundaryPath("missing-root"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected root missing failure, got %v", err)
	}
}

func TestInstallHookRefusesSymlinkBackup(t *testing.T) {
	dir := t.TempDir()
	hookPath := filepath.Join(dir, "pre-commit")
	if err := os.WriteFile(hookPath, []byte("#!/usr/bin/env bash\necho legacy\n"), 0o755); err != nil {
		t.Fatalf("write legacy hook: %v", err)
	}
	if err := os.Symlink(filepath.Join(dir, "outside"), hookPath+".pre-hasp"); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := installHook(hookPath, true); err == nil || !strings.Contains(err.Error(), "refusing to overwrite symlink hook backup") {
		t.Fatalf("expected symlink backup refusal, got %v", err)
	}
}

func TestRefuseSymlinkPropagatesInspectErrors(t *testing.T) {
	longName := strings.Repeat("x", 5000)
	err := refuseSymlink(filepath.Join(t.TempDir(), longName), "hook")
	if err == nil || !strings.Contains(err.Error(), "inspect hook") {
		t.Fatalf("expected lstat inspect error, got %v", err)
	}
}
