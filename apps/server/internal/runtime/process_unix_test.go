//go:build unix

package runtime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestStartAndStopDetachedProcess(t *testing.T) {
	home := t.TempDir()
	socket := filepath.Join("/tmp", "hasp-process-test.sock")
	t.Setenv(paths.EnvHome, home)
	t.Setenv(paths.EnvSocket, socket)
	t.Setenv("HASP_TEST_HELPER_DAEMON", "1")
	t.Cleanup(func() {
		_ = os.Remove(socket)
	})

	if err := startDetachedProcess(context.Background()); err != nil {
		t.Fatalf("start detached process: %v", err)
	}
	manager, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := waitForSocket(manager.SocketPath(), 2*time.Second); err != nil {
		t.Fatalf("wait for socket: %v", err)
	}
	if err := stopDetachedProcess(); err != nil {
		t.Fatalf("stop detached process: %v", err)
	}
}

func TestDetachedDaemonReapedWhileParentLives(t *testing.T) {
	lockRuntimeSeams(t)
	dir, err := os.MkdirTemp("/tmp", "hasp-reap-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv(paths.EnvHome, dir)
	t.Setenv(paths.EnvSocket, filepath.Join(dir, "daemon.sock"))
	t.Setenv("HASP_TEST_HELPER_DAEMON", "1")
	if err := startDetachedProcess(context.Background()); err != nil {
		t.Fatal(err)
	}
	resolved, err := paths.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if err := waitForSocket(resolved.SocketPath, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(resolved.PidFilePath)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		_, _ = syscall.Wait4(pid, nil, syscall.WNOHANG, nil)
	})
	// The long-lived spawner stays alive and does not call StopDaemon/Wait.
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("daemon pid %d was not reaped while its parent stayed alive", pid)
}

func TestStopDetachedProcessAcceptsExistingZombie(t *testing.T) {
	lockRuntimeSeams(t)
	t.Setenv(paths.EnvHome, t.TempDir())
	t.Setenv(paths.EnvSocket, filepath.Join(t.TempDir(), "absent.sock"))
	cmd := exec.Command("sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Wait() })
	deadline := time.Now().Add(3 * time.Second)
	for {
		out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(cmd.Process.Pid)).Output()
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(strings.TrimSpace(string(out)), "Z") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not become a zombie")
		}
		time.Sleep(10 * time.Millisecond)
	}
	resolved, err := paths.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(resolved.RuntimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolved.PidFilePath, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	if processStillRunning(cmd.Process) {
		t.Error("zombie reported as running")
	}
	if err := stopDetachedProcess(); err != nil {
		t.Fatalf("stop an exited daemon with no socket: %v", err)
	}
}
