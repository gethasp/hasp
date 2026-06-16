package hooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
