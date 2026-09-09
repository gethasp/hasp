package hooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectReportsUnavailableGitMetadata(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	original := hooksCommonDir
	hooksCommonDir = func(context.Context, string) (string, error) { return "", os.ErrPermission }
	t.Cleanup(func() { hooksCommonDir = original })
	got := Inspect(root)
	if got.State != "unavailable" || got.Ready || got.PreCommit.Detail == "" {
		t.Fatalf("unavailable metadata: %+v", got)
	}
	if got := inspectHook("\x00"); got.State != "unreadable" || got.Detail == "" {
		t.Fatalf("invalid path: %+v", got)
	}
}

func TestInstallHookReportsFilesystemFailures(t *testing.T) {
	for _, step := range []string{"read existing hook", "inspect existing hook", "preserve saved hook permissions", "make hook executable"} {
		t.Run(step, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pre-commit")
			originalStat, originalChmod := hooksStat, hooksChmod
			t.Cleanup(func() { hooksStat, hooksChmod = originalStat, originalChmod })
			if step == "read existing hook" {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 23\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if step == "inspect existing hook" {
				hooksStat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
			}
			hooksChmod = func(name string, mode os.FileMode) error {
				if step == "preserve saved hook permissions" && name != path {
					return os.ErrPermission
				}
				if step == "make hook executable" && name == path {
					return os.ErrPermission
				}
				return originalChmod(name, mode)
			}
			err := installHook(path, true)
			if err == nil || !strings.Contains(err.Error(), step) {
				t.Fatalf("%s: %v", step, err)
			}
			if step != "read existing hook" && !errors.Is(err, os.ErrPermission) {
				t.Fatalf("lost underlying error: %v", err)
			}
			if step == "inspect existing hook" || step == "preserve saved hook permissions" {
				content, readErr := os.ReadFile(path)
				if readErr != nil || string(content) != "#!/bin/sh\nexit 23\n" {
					t.Fatalf("original hook changed after failed backup: %q, %v", content, readErr)
				}
			}
		})
	}
}
