package hooks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrePushPreservesUpdatesArgumentsFailureAndCleanup(t *testing.T) {
	for _, installer := range []string{"go", "shell"} {
		t.Run(installer, func(t *testing.T) {
			for _, legacyExit := range []string{"0", "43"} {
				t.Run(legacyExit, func(t *testing.T) {
					root := t.TempDir()
					runGit(t, root, "init")
					hook := filepath.Join(mustHooksDir(t, root), "pre-push")
					writeHookFixture(t, hook, "#!/bin/sh\nprintf '%s\\n' \"$@\" > legacy-args\ncat > legacy-input\nexit "+legacyExit+"\n")
					if err := installForHookReplay(t, root, installer); err != nil {
						t.Fatal(err)
					}
					bin, tmp := t.TempDir(), t.TempDir()
					writeHookFixture(t, filepath.Join(bin, "hasp"), `#!/bin/sh
[ "$1" = check-repo ] && [ "$4" = --pre-push ] && [ "$5" = --remote ] && [ "$6" = origin ] && [ "$7" = --fail-on-skipped ] || exit 90
cat > scanner-input
exit 42
`)
					input := "refs/heads/main " + strings.Repeat("a", 40) + " refs/heads/main " + strings.Repeat("0", 40) + "\n(delete) " + strings.Repeat("0", 40) + " refs/heads/old " + strings.Repeat("b", 40) + "\n"
					cmd := exec.Command(hook, "origin", "/remote with spaces/repo")
					cmd.Dir = root
					cmd.Stdin = strings.NewReader(input)
					cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "TMPDIR="+tmp)
					out, err := cmd.CombinedOutput()
					wantExit := 42
					if legacyExit == "43" {
						wantExit = 43
					}
					exit, ok := err.(*exec.ExitError)
					if !ok || exit.ExitCode() != wantExit {
						t.Fatalf("exit = %v, output %s", err, out)
					}
					for path, want := range map[string]string{"legacy-args": "origin\n/remote with spaces/repo\n", "legacy-input": input} {
						got, err := os.ReadFile(filepath.Join(root, path))
						if err != nil || string(got) != want {
							t.Fatalf("%s = %q, %v", path, got, err)
						}
					}
					got, err := os.ReadFile(filepath.Join(root, "scanner-input"))
					if legacyExit == "0" && (err != nil || string(got) != input) {
						t.Fatalf("scanner lost stdin: %q, %v", got, err)
					}
					if legacyExit == "43" && !os.IsNotExist(err) {
						t.Fatal("scanner ran despite saved hook failure")
					}
					left, err := os.ReadDir(tmp)
					if err != nil || len(left) != 0 {
						t.Fatalf("temporary stdin files remain: %v, %v", left, err)
					}
				})
			}

		})
	}
}
