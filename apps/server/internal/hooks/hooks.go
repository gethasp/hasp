package hooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/gitsafe"
)

const marker = "# HASP-MANAGED-HOOK"

var hooksMkdirAll = os.MkdirAll

var (
	ErrNotGitRepo     = errors.New("not a git working tree")
	ErrHooksDisabled  = errors.New("git hooks are disabled")
	ErrUnsafeHooksDir = errors.New("git hooks path is outside the project boundary")
)

type InstallPlan struct {
	ProjectRoot string
	HooksDir    string
}

func Install(projectRoot string) error {
	plan, err := ResolveInstallPlan(projectRoot)
	if err != nil {
		return err
	}
	if err := hooksMkdirAll(plan.HooksDir, 0o755); err != nil {
		return fmt.Errorf("create hooks dir: %w", err)
	}
	// pre-commit scans the staged index (what the commit will contain); pre-push
	// keeps the working-tree scan for now (committed-range scanning is a follow-up).
	for _, h := range []struct {
		name   string
		staged bool
	}{{"pre-commit", true}, {"pre-push", false}} {
		if err := installHook(filepath.Join(plan.HooksDir, h.name), h.staged); err != nil {
			return err
		}
	}
	return nil
}

func ResolveInstallPlan(projectRoot string) (InstallPlan, error) {
	root, err := gitTopLevel(projectRoot)
	if err != nil {
		return InstallPlan{}, fmt.Errorf("%w: %v", ErrNotGitRepo, err)
	}
	commonDir, err := gitsafe.CommonDir(context.Background(), projectRoot)
	if err != nil {
		return InstallPlan{}, err
	}
	hooksPath, hasHooksPath, err := gitsafe.CoreHooksPath(context.Background(), projectRoot)
	if err != nil {
		return InstallPlan{}, err
	}
	hooksDir := filepath.Join(commonDir, "hooks")
	if hasHooksPath {
		hooksDir, err = resolveCustomHooksDir(root, commonDir, hooksPath)
		if err != nil {
			return InstallPlan{}, err
		}
	}
	return InstallPlan{ProjectRoot: root, HooksDir: hooksDir}, nil
}

func ManagedHooksPresent(projectRoot string) bool {
	plan, err := ResolveInstallPlan(projectRoot)
	if err != nil {
		return false
	}
	for _, hookName := range []string{"pre-commit", "pre-push"} {
		data, err := os.ReadFile(filepath.Join(plan.HooksDir, hookName))
		if err != nil || !strings.Contains(string(data), marker) {
			return false
		}
	}
	return true
}

func resolveCustomHooksDir(projectRoot, commonDir, hooksPath string) (string, error) {
	value := strings.TrimSpace(hooksPath)
	if value == "" {
		return "", fmt.Errorf("%w: core.hooksPath is empty", ErrHooksDisabled)
	}
	if filepath.Clean(value) == "/dev/null" {
		return "", fmt.Errorf("%w: core.hooksPath is /dev/null", ErrHooksDisabled)
	}
	var hooksDir string
	if filepath.IsAbs(value) {
		hooksDir = filepath.Clean(value)
	} else {
		hooksDir = filepath.Clean(filepath.Join(projectRoot, value))
	}
	canonicalHooksDir, err := canonicalBoundaryPath(hooksDir)
	if err != nil {
		return "", fmt.Errorf("resolve hooks path: %w", err)
	}
	canonicalProjectRoot, err := canonicalBoundaryPath(projectRoot)
	if err != nil {
		return "", fmt.Errorf("resolve project root: %w", err)
	}
	canonicalCommonDir, err := canonicalBoundaryPath(commonDir)
	if err != nil {
		return "", fmt.Errorf("resolve git common dir: %w", err)
	}
	if isChildPath(canonicalHooksDir, canonicalProjectRoot) || isChildPath(canonicalHooksDir, canonicalCommonDir) {
		return hooksDir, nil
	}
	return "", fmt.Errorf("%w: %s", ErrUnsafeHooksDir, hooksDir)
}

func canonicalBoundaryPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	probe := filepath.Clean(abs)
	missing := make([]string, 0)
	for {
		resolved, err := filepath.EvalSymlinks(probe)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return "", err
		}
		missing = append(missing, filepath.Base(probe))
		probe = parent
	}
}

func isChildPath(path, base string) bool {
	rel, err := filepath.Rel(base, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

func installHook(path string, staged bool) error {
	if err := refuseSymlink(path, "hook"); err != nil {
		return err
	}
	existing, err := os.ReadFile(path)
	if err == nil && !strings.Contains(string(existing), marker) {
		backup := path + ".pre-hasp"
		if err := refuseSymlink(backup, "hook backup"); err != nil {
			return err
		}
		if err := os.WriteFile(backup, existing, 0o755); err != nil {
			return fmt.Errorf("backup existing hook: %w", err)
		}
	}
	backup := path + ".pre-hasp"
	stagedFlag := ""
	if staged {
		stagedFlag = " --staged"
	}
	content := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
%s
project_root="$(git -c core.hooksPath=/dev/null -c safe.directory='*' rev-parse --show-toplevel 2>/dev/null || pwd)"
hasp check-repo --project-root "$project_root"%s
if [[ -x %s ]]; then
  %s "$@"
fi
`, marker, stagedFlag, shellSingleQuote(backup), shellSingleQuote(backup))
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		return fmt.Errorf("write hook: %w", err)
	}
	return nil
}

func refuseSymlink(path string, label string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlink %s: %s", label, path)
	}
	return nil
}

// shellSingleQuote wraps s in single quotes, escaping any embedded single quote
// as '\” so the result is a single shell word with no interpretation of $, `,
// or other metacharacters.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func gitTopLevel(projectRoot string) (string, error) {
	out, err := gitsafe.TopLevelCached(context.Background(), projectRoot)
	if err != nil {
		return "", fmt.Errorf("resolve git top-level: %w", err)
	}
	return out, nil
}
