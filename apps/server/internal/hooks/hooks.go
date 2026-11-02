package hooks

import (
	"bytes"
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
var hooksStat = os.Stat
var hooksChmod = os.Chmod
var hooksAbs = filepath.Abs
var hooksEvalSymlinks = filepath.EvalSymlinks
var hooksCommonDir = gitsafe.CommonDir
var hooksCoreHooksPath = gitsafe.CoreHooksPath

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
	// Each gate scans Git's pending content after the saved hook succeeds.
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
	commonDir, err := hooksCommonDir(context.Background(), projectRoot)
	if err != nil {
		return InstallPlan{}, err
	}
	hooksPath, hasHooksPath, err := hooksCoreHooksPath(context.Background(), projectRoot)
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
	return Inspect(projectRoot).Installed
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
	abs, err := hooksAbs(path)
	if err != nil {
		return "", err
	}
	probe := filepath.Clean(abs)
	missing := make([]string, 0)
	for {
		resolved, err := hooksEvalSymlinks(probe)
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
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read existing hook: %w", err)
	}
	if err == nil && !strings.Contains(string(existing), marker) {
		backup := path + ".pre-hasp"
		if err := refuseSymlink(backup, "hook backup"); err != nil {
			return err
		}
		info, err := hooksStat(path)
		if err != nil {
			return fmt.Errorf("inspect existing hook: %w", err)
		}
		previous, readErr := os.ReadFile(backup)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return fmt.Errorf("read saved hook: %w", readErr)
		}
		if !bytes.Equal(previous, existing) || readErr != nil {
			if readErr == nil {
				backupInfo, err := hooksStat(backup)
				if err != nil {
					return fmt.Errorf("inspect saved hook: %w", err)
				}
				saved, err := saveReplacedHook(backup, previous, backupInfo.Mode().Perm())
				if err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "warning: replacing saved hook %s; saved previous content to %s; merge custom gates into %s to keep them active\n", backup, saved, backup)
			}
			if err := os.WriteFile(backup, existing, info.Mode().Perm()); err != nil {
				return fmt.Errorf("backup existing hook: %w", err)
			}
			if err := hooksChmod(backup, info.Mode().Perm()); err != nil {
				return fmt.Errorf("preserve saved hook permissions: %w", err)
			}
		}
	}
	backup := path + ".pre-hasp"
	input := ""
	if !staged {
		input = ` < "$updates_file"`
	}
	chain := fmt.Sprintf(`if [[ -x %s ]]; then
  %s "$@"%s
elif [[ -e %s || -L %s ]]; then
  printf 'warning: saved hook is not executable: %%s; custom gates were skipped\n' %s >&2
fi
`, shellSingleQuote(backup), shellSingleQuote(backup), input, shellSingleQuote(backup), shellSingleQuote(backup), shellSingleQuote(backup))
	content := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
%s
%s
project_root="$(git -c core.hooksPath=/dev/null -c safe.directory='*' rev-parse --show-toplevel 2>/dev/null || pwd)"
%shasp check-repo --project-root "$project_root" --staged
`, marker, revisionMarker, chain)
	if !staged {
		content = fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
%s
%s
project_root="$(git -c core.hooksPath=/dev/null -c safe.directory='*' rev-parse --show-toplevel 2>/dev/null || pwd)"
updates_file="$(umask 077; mktemp "${TMPDIR:-/tmp}/hasp-pre-push.XXXXXX")"
trap 'rm -f "$updates_file"' EXIT
trap 'exit 1' HUP INT TERM
cat > "$updates_file"
%shasp check-repo --project-root "$project_root" --pre-push --remote "$1" --fail-on-skipped < "$updates_file"
`, marker, revisionMarker, chain)
	}
	if bytes.Equal(existing, []byte(content)) {
		info, err := hooksStat(path)
		if err != nil {
			return fmt.Errorf("inspect existing hook: %w", err)
		}
		if info.Mode().Perm()&0o111 != 0o111 {
			if err := hooksChmod(path, 0o755); err != nil {
				return fmt.Errorf("make hook executable: %w", err)
			}
		}
		return nil
	}
	if strings.Contains(string(existing), marker) {
		saved, err := saveReplacedHook(path, existing, 0o600)
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "warning: replacing changed HASP hook %s; saved previous content to %s; move custom gates into %s to keep them active\n", path, saved, backup)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		return fmt.Errorf("write hook: %w", err)
	}
	if err := hooksChmod(path, 0o755); err != nil {
		return fmt.Errorf("make hook executable: %w", err)
	}
	return nil
}

func saveReplacedHook(path string, content []byte, mode os.FileMode) (string, error) {
	saved, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".hasp-replaced-*")
	if err != nil {
		return "", fmt.Errorf("backup replaced hook: %w", err)
	}
	_, writeErr := saved.Write(content)
	chmodErr := saved.Chmod(mode)
	closeErr := saved.Close()
	if err := errors.Join(writeErr, chmodErr, closeErr); err != nil {
		return "", fmt.Errorf("backup replaced hook %s: %w", saved.Name(), err)
	}
	return saved.Name(), nil
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
