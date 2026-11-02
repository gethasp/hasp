package hooks

import (
	"bytes"
	"os"
	"os/exec"
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

func TestInstallRetainsReplacedSavedGate(t *testing.T) {
	for _, installer := range []string{"go", "shell"} {
		t.Run(installer, func(t *testing.T) {
			warnings, err := os.CreateTemp(t.TempDir(), "warnings")
			if err != nil {
				t.Fatal(err)
			}
			stderr := os.Stderr
			os.Stderr = warnings
			t.Cleanup(func() { os.Stderr = stderr; _ = warnings.Close() })
			root := t.TempDir()
			runGit(t, root, "init")
			path := filepath.Join(mustHooksDir(t, root), "pre-push")
			writeHookFixture(t, path, "#!/bin/sh\necho original-gate\n")
			if err := installForHookReplay(t, root, installer); err != nil {
				t.Fatal(err)
			}
			gate := "#!/bin/sh\necho custom-gate\n"
			writeHookFixture(t, path+".pre-hasp", gate)
			incoming := "#!/bin/sh\necho replacement-gate\n"
			writeHookFixture(t, path, incoming)
			if err := installForHookReplay(t, root, installer); err != nil {
				t.Fatal(err)
			}
			backups, err := filepath.Glob(path + ".pre-hasp.hasp-replaced-*")
			if err != nil || len(backups) != 1 {
				t.Fatalf("saved gate lost: %v, %v", backups, err)
			}
			warning, err := os.ReadFile(warnings.Name())
			if err != nil || !strings.Contains(string(warning), backups[0]) || !strings.Contains(string(warning), "merge") {
				t.Fatalf("missing saved-gate warning: %s, %v", warning, err)
			}
			content, err := os.ReadFile(backups[0])
			if err != nil || string(content) != gate {
				t.Fatalf("saved gate content: %q, %v", content, err)
			}
			saved := path + ".pre-hasp"
			content, err = os.ReadFile(saved)
			if err != nil || string(content) != incoming {
				t.Fatalf("incoming gate: %q, %v", content, err)
			}
			stamp := time.Unix(1234567890, 0)
			if err := os.Chtimes(saved, stamp, stamp); err != nil {
				t.Fatal(err)
			}
			writeHookFixture(t, path, incoming)
			if err := installForHookReplay(t, root, installer); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(saved)
			if err != nil || !info.ModTime().Equal(stamp) {
				t.Fatalf("identical saved gate rewritten: %v, %v", info, err)
			}
		})
	}
}

func TestManagedHooksWarnForNonExecutableSavedGate(t *testing.T) {
	for _, installer := range []string{"go", "shell"} {
		for _, hook := range []string{"pre-commit", "pre-push"} {
			t.Run(installer+"/"+hook, func(t *testing.T) {
				root := t.TempDir()
				runGit(t, root, "init")
				if err := installForHookReplay(t, root, installer); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(mustHooksDir(t, root), hook)
				if err := os.WriteFile(path+".pre-hasp", []byte("#!/bin/sh\nexit 43\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				bin := t.TempDir()
				writeHookFixture(t, filepath.Join(bin, "hasp"), "#!/bin/sh\nexit 0\n")
				cmd := exec.Command(path, "origin", "/remote")
				cmd.Dir = root
				cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
				out, err := cmd.CombinedOutput()
				if err != nil || !strings.Contains(string(out), path+".pre-hasp") || !strings.Contains(string(out), "not executable") {
					t.Fatalf("missing warning: %s, %v", out, err)
				}
			})
		}
	}
}

func TestFailedSavedGateBackupLeavesBothHooksIntact(t *testing.T) {
	// Both existing names fit the filesystem limit, but a unique backup cannot.
	path := filepath.Join(t.TempDir(), strings.Repeat("h", 230))
	incoming, previous := "#!/bin/sh\nexit 12\n", "#!/bin/sh\nexit 34\n"
	writeHookFixture(t, path, incoming)
	writeHookFixture(t, path+".pre-hasp", previous)
	if err := installHook(path, false); err == nil || !strings.Contains(err.Error(), "backup replaced hook") {
		t.Fatalf("expected backup failure: %v", err)
	}
	for name, want := range map[string]string{path: incoming, path + ".pre-hasp": previous} {
		got, err := os.ReadFile(name)
		if err != nil || string(got) != want {
			t.Fatalf("hook changed after failed backup: %q, %v", got, err)
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
