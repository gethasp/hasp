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
	// pre-commit scans the staged index (hasp-8buu); pre-push keeps the
	// working-tree scan until committed-range scanning lands.
	if !strings.Contains(string(managed), "--staged") {
		t.Fatalf("pre-commit hook should pass --staged: %s", string(managed))
	}
	if strings.Contains(string(prePush), "--staged") {
		t.Fatalf("pre-push hook should not pass --staged yet: %s", string(prePush))
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

// TestInstallHookDoesNotShellInjectProjectRoot guards against command
// substitution in the generated hook (hasp-g84c). A project path containing
// $(...) must be embedded as an inert single-quoted literal, not executed when
// git runs the hook.
func TestInstallHookDoesNotShellInjectProjectRoot(t *testing.T) {
	dir := t.TempDir()
	hookPath := filepath.Join(dir, "pre-commit")
	malicious := "/repo$(touch INJECTED)"

	if err := installHook(hookPath, malicious, true); err != nil {
		t.Fatalf("installHook: %v", err)
	}

	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read hook: %v", err)
	}
	// The path must appear single-quoted (no bash interpretation of $()).
	if !strings.Contains(string(content), "'"+malicious+"'") {
		t.Fatalf("project root not single-quoted in hook:\n%s", string(content))
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
