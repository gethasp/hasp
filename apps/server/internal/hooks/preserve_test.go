package hooks

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInstallPreservesCurrentHooksAcrossWorktrees(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "main")
	worktree := filepath.Join(parent, "worktree")
	runGit(t, parent, "init", root)
	runGit(t, root, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "init")
	runGit(t, root, "worktree", "add", worktree)
	if err := Install(root); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pre-commit", "pre-push"} {
		path := filepath.Join(mustHooksDir(t, root), name)
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		stamp := time.Unix(1234567890, 0)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		for _, installRoot := range []string{root, worktree} {
			if err := Install(installRoot); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) || !info.ModTime().Equal(stamp) {
				t.Fatalf("install from %s rewrote current %s", installRoot, name)
			}
		}
	}
}

func TestInstallBacksUpEditedManagedHooksAndReportsPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre-push")
	if err := installHook(path, false); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	warnings := filepath.Join(t.TempDir(), "warnings")
	output, err := os.Create(warnings)
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr
	os.Stderr = output
	t.Cleanup(func() { os.Stderr = stderr; _ = output.Close() })
	for _, extra := range []string{"\necho first-custom-gate\n", "\necho second-custom-gate\n"} {
		edited := append(append([]byte(nil), current...), extra...)
		if err := os.WriteFile(path, edited, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := installHook(path, false); err != nil {
			t.Fatal(err)
		}
		backups, err := filepath.Glob(path + ".hasp-replaced-*")
		if err != nil {
			t.Fatal(err)
		}
		reported, err := os.ReadFile(warnings)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, backup := range backups {
			data, err := os.ReadFile(backup)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(data, edited) && strings.Contains(string(reported), backup) {
				found = true
			}
		}
		if !found {
			t.Fatalf("edited hook was not backed up and reported: %s", reported)
		}
	}
	backups, _ := filepath.Glob(path + ".hasp-replaced-*")
	if len(backups) != 2 {
		t.Fatalf("want two retained backups, got %v", backups)
	}
}
