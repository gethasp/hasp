package hooks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedHooksPresentRejectsNonExecutableHook(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	if err := Install(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(mustHooksDir(t, root), "pre-push")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if ManagedHooksPresent(root) {
		t.Fatal("a non-executable pre-push hook was reported installed")
	}
	if err := Install(root); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("reinstallation did not restore execution: %v, %v", info, err)
	}
}

func TestInstallPreservesDisabledSavedHook(t *testing.T) {
	for _, installer := range []string{"go", "shell"} {
		t.Run(installer, func(t *testing.T) {
			root := t.TempDir()
			runGit(t, root, "init")
			path := filepath.Join(mustHooksDir(t, root), "pre-commit")
			if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 43\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := installForHookReplay(t, root, installer); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path + ".pre-hasp")
			if err != nil || info.Mode().Perm()&0o111 != 0 {
				t.Fatalf("disabled saved hook became executable: %v, %v", info, err)
			}
		})
	}
}

func TestInspectReportsIndividualStatesWithoutRunningHooks(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	if got := Inspect(root); got.State != "missing" || got.PreCommit.State != "missing" || got.PrePush.State != "missing" {
		t.Fatalf("missing: %+v", got)
	}
	if err := Install(root); err != nil {
		t.Fatal(err)
	}
	got := Inspect(root)
	if got.State != "ready" || !got.Ready || !got.Installed || got.ScanState != "not_run" {
		t.Fatalf("complete: %+v", got)
	}
	push := filepath.Join(mustHooksDir(t, root), "pre-push")
	if err := os.Remove(push); err != nil {
		t.Fatal(err)
	}
	got = Inspect(root)
	if got.State != "partial" || got.PreCommit.State != "ready" || got.PrePush.State != "missing" || got.Installed || got.Ready || got.Repair == "" {
		t.Fatalf("partial: %+v", got)
	}
	writeHookFixture(t, push, "#!/bin/sh\ntouch hook-was-run\n")
	got = Inspect(root)
	if got.PrePush.State != "custom_unverified" || !got.PrePush.Executable || got.Installed {
		t.Fatalf("custom: %+v", got)
	}
	writeHookFixture(t, push, "#!/bin/sh\n"+marker+"\ntouch hook-was-run\n")
	got = Inspect(root)
	if got.State != "outdated" || !got.Installed || got.Ready || got.PrePush.Current {
		t.Fatalf("outdated: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(root, "hook-was-run")); !os.IsNotExist(err) {
		t.Fatal("diagnostics executed the hook")
	}
	if err := os.Chmod(push, 0o600); err != nil {
		t.Fatal(err)
	}
	got = Inspect(root)
	if got.PrePush.State != "not_executable" || got.Installed || got.Ready {
		t.Fatalf("non-executable: %+v", got)
	}
	if err := Install(root); err != nil {
		t.Fatal(err)
	}
	if got := Inspect(root); !got.Ready {
		t.Fatalf("repaired: %+v", got)
	}
	runGit(t, root, "config", "core.hooksPath", "/dev/null")
	got = Inspect(root)
	if got.State != "disabled" || got.PreCommit.State != "disabled" || got.Installed || got.Ready {
		t.Fatalf("disabled: %+v", got)
	}
	runGit(t, root, "config", "core.hooksPath", t.TempDir())
	if got := Inspect(root); got.State != "unsafe_path" || got.Ready {
		t.Fatalf("unsafe: %+v", got)
	}
	if got := Inspect(t.TempDir()); got.State != "not_git" || got.Ready {
		t.Fatalf("non-Git: %+v", got)
	}
}

func TestInspectDoesNotTreatSymlinksOrUnreadableHooksAsReady(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init")
	if err := Install(root); err != nil {
		t.Fatal(err)
	}
	push := filepath.Join(mustHooksDir(t, root), "pre-push")
	if os.Geteuid() != 0 {
		if err := os.Chmod(push, 0o000); err != nil {
			t.Fatal(err)
		}
		got := Inspect(root)
		if got.PrePush.State != "unreadable" || got.Installed || got.Ready {
			t.Fatalf("unreadable: %+v", got)
		}
	}
	if err := os.Remove(push); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(mustHooksDir(t, root), "pre-commit"), push); err != nil {
		t.Fatal(err)
	}
	if got := Inspect(root); got.PrePush.State != "custom_unverified" || got.Ready || got.Installed {
		t.Fatalf("symlink: %+v", got)
	}
}
