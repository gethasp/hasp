package hooks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreCommitScansIndexAfterChainedHook(t *testing.T) {
	for _, installer := range []string{"go", "shell"} {
		t.Run(installer, func(t *testing.T) {
			root := t.TempDir()
			runGit(t, root, "init")
			runGit(t, root, "config", "user.email", "test@example.com")
			runGit(t, root, "config", "user.name", "Test")
			writeHookFixture(t, filepath.Join(root, "safe.txt"), "safe\n")
			runGit(t, root, "add", "safe.txt")
			legacy := filepath.Join(mustHooksDir(t, root), "pre-commit")
			writeHookFixture(t, legacy, "#!/bin/sh\nprintf 'synthetic-chained-credential' > added-by-hook.txt\ngit add added-by-hook.txt\n")
			if err := installForHookReplay(t, root, installer); err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			// The scanner checks the actual index Git will commit, after the saved hook.
			writeHookFixture(t, filepath.Join(bin, "hasp"), `#!/bin/sh
[ "$1" = check-repo ] && [ "$2" = --project-root ] && [ "$4" = --staged ] || exit 90
git show :added-by-hook.txt > scanned-index.txt 2>/dev/null || exit 0
if [ "$(cat scanned-index.txt)" = synthetic-chained-credential ]; then exit 42; fi
`)
			cmd := exec.Command("git", "-C", root, "commit", "-m", "must be blocked")
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("commit accepted a credential staged by the saved hook: %s", out)
			}
			got, err := os.ReadFile(filepath.Join(root, "scanned-index.txt"))
			if err != nil || string(got) != "synthetic-chained-credential" {
				t.Fatalf("scanner did not inspect final index: %q, %v", got, err)
			}
			if err := exec.Command("git", "-C", root, "rev-parse", "--verify", "HEAD").Run(); err == nil {
				t.Fatal("blocked commit created HEAD")
			}

		})
	}
}

func TestPreCommitPreservesChainedFailureAndArguments(t *testing.T) {
	for _, installer := range []string{"go", "shell"} {
		t.Run(installer, func(t *testing.T) {
			root := t.TempDir()
			runGit(t, root, "init")
			legacy := filepath.Join(mustHooksDir(t, root), "pre-commit")
			writeHookFixture(t, legacy, "#!/bin/sh\nprintf '%s\\n' \"$@\" > args.txt\ncat > input.txt\nexit 43\n")
			if err := installForHookReplay(t, root, installer); err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			writeHookFixture(t, filepath.Join(bin, "hasp"), "#!/bin/sh\ntouch scanner-ran\n")
			cmd := exec.Command(legacy, "arg with space", "second")
			cmd.Dir = root
			cmd.Stdin = strings.NewReader("saved hook input\n")
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 43 {
				t.Fatalf("saved hook failure = %v, output %s", err, out)
			}
			for file, want := range map[string]string{"args.txt": "arg with space\nsecond\n", "input.txt": "saved hook input\n"} {
				got, err := os.ReadFile(filepath.Join(root, file))
				if err != nil || string(got) != want {
					t.Fatalf("%s = %q, %v", file, got, err)
				}
			}
			if _, err := os.Stat(filepath.Join(root, "scanner-ran")); !os.IsNotExist(err) {
				t.Fatal("scanner ran after saved hook failed")
			}

		})
	}
}

func writeHookFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func installForHookReplay(t *testing.T, root, installer string) error {
	t.Helper()
	if installer == "go" {
		return Install(root)
	}
	bundle := t.TempDir()
	scripts := filepath.Join(bundle, "scripts")
	if err := os.MkdirAll(scripts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(bundle, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hasp-install-hooks.sh", "hasp-common.sh", "hasp-pre-commit.sh", "hasp-pre-push.sh"} {
		data, err := os.ReadFile(filepath.Join("../../../../scripts", name))
		if err != nil {
			t.Fatal(err)
		}
		writeHookFixture(t, filepath.Join(scripts, name), string(data))
	}
	writeHookFixture(t, filepath.Join(bundle, "bin", "hasp"), "#!/bin/sh\nexec hasp \"$@\"\n")
	cmd := exec.Command("bash", filepath.Join(scripts, "hasp-install-hooks.sh"))
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shell hook install: %v: %s", err, out)
	}
	return nil
}
