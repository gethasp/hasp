package hooks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/gitsafe"
)

const marker = "# HASP-MANAGED-HOOK"

var hooksMkdirAll = os.MkdirAll

func Install(projectRoot string) error {
	root, err := gitTopLevel(projectRoot)
	if err != nil {
		return nil
	}
	hooksDir := filepath.Join(root, ".git", "hooks")
	if err := hooksMkdirAll(hooksDir, 0o755); err != nil {
		return fmt.Errorf("create hooks dir: %w", err)
	}
	// pre-commit scans the staged index (what the commit will contain); pre-push
	// keeps the working-tree scan for now (committed-range scanning is a follow-up).
	for _, h := range []struct {
		name   string
		staged bool
	}{{"pre-commit", true}, {"pre-push", false}} {
		if err := installHook(filepath.Join(hooksDir, h.name), root, h.staged); err != nil {
			return err
		}
	}
	return nil
}

func installHook(path, projectRoot string, staged bool) error {
	existing, err := os.ReadFile(path)
	if err == nil && !strings.Contains(string(existing), marker) {
		backup := path + ".pre-hasp"
		if err := os.WriteFile(backup, existing, 0o755); err != nil {
			return fmt.Errorf("backup existing hook: %w", err)
		}
	}
	// Shell-quote interpolated paths. Go's %q yields a double-quoted literal,
	// inside which bash still performs $(...) and `...` command substitution —
	// so a project path like /tmp/repo$(touch pwned) would execute on every
	// commit/push. Single-quote escaping disables all bash interpretation.
	backup := path + ".pre-hasp"
	stagedFlag := ""
	if staged {
		stagedFlag = " --staged"
	}
	content := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
%s
hasp check-repo --project-root %s%s
if [[ -x %s ]]; then
  %s "$@"
fi
`, marker, shellSingleQuote(projectRoot), stagedFlag, shellSingleQuote(backup), shellSingleQuote(backup))
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		return fmt.Errorf("write hook: %w", err)
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
