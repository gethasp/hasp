//go:build darwin || linux

package runner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPrepareRunDirRejectsHeldLockAndSymlink(t *testing.T) {
	lockRunnerSeams(t)
	original := randReadRunner
	randReadRunner = func(p []byte) (int, error) { clear(p); return len(p), nil }
	t.Cleanup(func() { randReadRunner = original })
	root := t.TempDir()
	path, cleanup, err := prepareRunInjectDir(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanup() })
	if got, noop, err := prepareRunInjectDir(root); err == nil || got != "" || !strings.Contains(err.Error(), "already in use") || noop() != nil {
		t.Fatalf("held lock: %q, %v", got, err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "untouched")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(path, ".active")); err != nil {
		t.Fatal(err)
	}
	if got, noop, err := prepareRunInjectDir(root); err == nil || got != "" || !strings.Contains(err.Error(), "lock run inject dir") || noop() != nil {
		t.Fatalf("symlink lock: %q, %v", got, err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "original" {
		t.Fatalf("lock target changed: %q, %v", data, err)
	}
}

func TestStaleRunDirLockFailures(t *testing.T) {
	lockRunnerSeams(t)
	original := statInjectedPath
	t.Cleanup(func() { statInjectedPath = original })
	for _, removed := range []bool{false, true} {
		root := t.TempDir()
		path := filepath.Join(root, "run-stale")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "target"), filepath.Join(path, ".active")); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-2 * staleRunDirThreshold)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		statInjectedPath = func(name string) (os.FileInfo, error) {
			info, err := original(name)
			if removed {
				if removeErr := os.RemoveAll(name); removeErr != nil {
					t.Fatal(removeErr)
				}
			}
			return info, err
		}
		err := cleanupStaleInjectedFiles(root)
		if removed && err != nil {
			t.Fatalf("concurrent removal: %v", err)
		}
		if !removed && (err == nil || !strings.Contains(err.Error(), "lock stale run dir")) {
			t.Fatalf("unsafe stale lock: %v", err)
		}
	}
}

func TestRunDirPropagatesUnexpectedFlockError(t *testing.T) {
	lockRunnerSeams(t)
	original := flockRunDir
	flockRunDir = func(int, int) error { return syscall.EIO }
	t.Cleanup(func() { flockRunDir = original })
	release, err := tryLockRunDir(t.TempDir())
	if release != nil || !errors.Is(err, syscall.EIO) {
		t.Fatalf("lock I/O failure: %v, release=%v", err, release != nil)
	}
}

func TestCancelFinishedProcessGroup(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), "sh", "-c", "exit 0")
	configureProcessGroup(cmd)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Cancel(); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("cancel reaped process: %v", err)
	}
}

func TestCleanupFailurePreservesUnknownChildOutcome(t *testing.T) {
	lockRunnerSeams(t)
	bootstrapRunDirHomeDir(t)
	oldWait, oldRemove := waitCommand, removeInjectedTree
	t.Cleanup(func() { waitCommand, removeInjectedTree = oldWait, oldRemove })
	var started *exec.Cmd
	waitCommand = func(cmd *exec.Cmd) error { started = cmd; return syscall.EIO }
	removeInjectedTree = func(string) error { return os.ErrPermission }
	t.Cleanup(func() {
		if started != nil {
			_ = started.Wait()
		}
	})
	_, err := Execute(context.Background(), Input{Command: []string{"sh", "-c", "exit 0"}, Files: map[string][]byte{"KEY_FILE": []byte("fixture")}})
	if !errors.Is(err, syscall.EIO) || !errors.Is(err, os.ErrPermission) || !strings.Contains(err.Error(), "command started; outcome is unknown") {
		t.Fatalf("lost uncertain outcome: %v", err)
	}
}
