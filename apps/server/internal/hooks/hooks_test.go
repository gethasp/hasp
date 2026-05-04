package hooks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallCreatesManagedHooksAndBacksUpExistingHook(t *testing.T) {
	projectRoot := t.TempDir()
	runGit(t, projectRoot, "init")
	hooksDir := filepath.Join(projectRoot, ".git", "hooks")
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
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v: %s", args, err, string(out))
	}
}
