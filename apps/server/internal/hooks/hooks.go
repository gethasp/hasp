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
	for _, name := range []string{"pre-commit", "pre-push"} {
		if err := installHook(filepath.Join(hooksDir, name), root); err != nil {
			return err
		}
	}
	return nil
}

func installHook(path, projectRoot string) error {
	existing, err := os.ReadFile(path)
	if err == nil && !strings.Contains(string(existing), marker) {
		backup := path + ".pre-hasp"
		if err := os.WriteFile(backup, existing, 0o755); err != nil {
			return fmt.Errorf("backup existing hook: %w", err)
		}
	}
	content := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
%s
hasp check-repo --project-root %q
if [[ -x %q ]]; then
  %q "$@"
fi
`, marker, projectRoot, path+".pre-hasp", path+".pre-hasp")
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		return fmt.Errorf("write hook: %w", err)
	}
	return nil
}

func gitTopLevel(projectRoot string) (string, error) {
	out, err := gitsafe.TopLevelCached(context.Background(), projectRoot)
	if err != nil {
		return "", fmt.Errorf("resolve git top-level: %w", err)
	}
	return out, nil
}
