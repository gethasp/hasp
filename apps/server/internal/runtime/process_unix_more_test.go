//go:build unix

package runtime

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

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestStartDetachedProcessFailurePaths(t *testing.T) {
	lockRuntimeSeams(t)
	t.Run("test binary without helper guard", func(t *testing.T) {
		t.Setenv("HASP_TEST_HELPER_DAEMON", "")

		if err := startDetachedProcess(context.Background()); err == nil || !strings.Contains(err.Error(), "refusing to start test daemon") {
			t.Fatalf("expected test daemon guard error, got %v", err)
		}
	})

	t.Run("resolve paths failure", func(t *testing.T) {
		origResolve := resolveRuntimePaths
		defer func() { resolveRuntimePaths = origResolve }()

		resolveRuntimePaths = func() (paths.Paths, error) {
			return paths.Paths{}, errors.New("resolve failed")
		}

		if err := startDetachedProcess(context.Background()); err == nil || !strings.Contains(err.Error(), "resolve failed") {
			t.Fatalf("expected resolve error, got %v", err)
		}
	})

	t.Run("mkdir failure", func(t *testing.T) {
		origResolve := resolveRuntimePaths
		origMkdir := runtimeMkdirAll
		defer func() {
			resolveRuntimePaths = origResolve
			runtimeMkdirAll = origMkdir
		}()

		resolveRuntimePaths = func() (paths.Paths, error) {
			dir := t.TempDir()
			return paths.Paths{
				RuntimeDir:  dir,
				PidFilePath: filepath.Join(dir, "daemon.pid"),
			}, nil
		}
		runtimeMkdirAll = func(string, os.FileMode) error { return errors.New("mkdir failed") }

		if err := startDetachedProcess(context.Background()); err == nil || !strings.Contains(err.Error(), "create runtime dir: mkdir failed") {
			t.Fatalf("expected mkdir error, got %v", err)
		}
	})

	t.Run("start failure", func(t *testing.T) {
		origResolve := resolveRuntimePaths
		origMkdir := runtimeMkdirAll
		origExec := execCommand
		defer func() {
			resolveRuntimePaths = origResolve
			runtimeMkdirAll = origMkdir
			execCommand = origExec
		}()

		resolveRuntimePaths = func() (paths.Paths, error) {
			dir := t.TempDir()
			return paths.Paths{
				RuntimeDir:  dir,
				PidFilePath: filepath.Join(dir, "daemon.pid"),
			}, nil
		}
		runtimeMkdirAll = func(string, os.FileMode) error { return nil }
		execCommand = func(string, ...string) *exec.Cmd {
			return exec.Command("/definitely-missing-hasp-binary")
		}

		if err := startDetachedProcess(context.Background()); err == nil || !strings.Contains(err.Error(), "start daemon") {
			t.Fatalf("expected start error, got %v", err)
		}
	})

	t.Run("write pid failure", func(t *testing.T) {
		origResolve := resolveRuntimePaths
		origMkdir := runtimeMkdirAll
		origExec := execCommand
		origWrite := writeFile
		defer func() {
			resolveRuntimePaths = origResolve
			runtimeMkdirAll = origMkdir
			execCommand = origExec
			writeFile = origWrite
		}()

		resolveRuntimePaths = func() (paths.Paths, error) {
			dir := t.TempDir()
			return paths.Paths{
				RuntimeDir:  dir,
				PidFilePath: filepath.Join(dir, "daemon.pid"),
			}, nil
		}
		runtimeMkdirAll = func(string, os.FileMode) error { return nil }
		execCommand = func(string, ...string) *exec.Cmd {
			return exec.Command("sh", "-c", "exit 0")
		}
		writeFile = func(string, []byte, os.FileMode) error { return errors.New("write failed") }

		if err := startDetachedProcess(context.Background()); err == nil || !strings.Contains(err.Error(), "write pid file: write failed") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("release failure", func(t *testing.T) {
		origResolve := resolveRuntimePaths
		origMkdir := runtimeMkdirAll
		origExec := execCommand
		origWrite := writeFile
		origRelease := releaseProcess
		defer func() {
			resolveRuntimePaths = origResolve
			runtimeMkdirAll = origMkdir
			execCommand = origExec
			writeFile = origWrite
			releaseProcess = origRelease
		}()

		resolveRuntimePaths = func() (paths.Paths, error) {
			dir := t.TempDir()
			return paths.Paths{
				RuntimeDir:  dir,
				PidFilePath: filepath.Join(dir, "daemon.pid"),
			}, nil
		}
		runtimeMkdirAll = func(string, os.FileMode) error { return nil }
		execCommand = func(string, ...string) *exec.Cmd {
			return exec.Command("sh", "-c", "exit 0")
		}
		writeFile = func(string, []byte, os.FileMode) error { return nil }
		releaseProcess = func(*os.Process) error { return errors.New("release failed") }

		if err := startDetachedProcess(context.Background()); err == nil || !strings.Contains(err.Error(), "release failed") {
			t.Fatalf("expected release error, got %v", err)
		}
	})
}

func TestStopDetachedProcessFailurePaths(t *testing.T) {
	lockRuntimeSeams(t)
	t.Run("resolve paths failure", func(t *testing.T) {
		origResolve := resolveRuntimePaths
		defer func() { resolveRuntimePaths = origResolve }()

		resolveRuntimePaths = func() (paths.Paths, error) {
			return paths.Paths{}, errors.New("resolve failed")
		}

		if err := stopDetachedProcess(); err == nil || !strings.Contains(err.Error(), "resolve failed") {
			t.Fatalf("expected resolve error, got %v", err)
		}
	})

	t.Run("read pid failure", func(t *testing.T) {
		origResolve := resolveRuntimePaths
		origRead := processReadFile
		defer func() {
			resolveRuntimePaths = origResolve
			processReadFile = origRead
		}()

		resolveRuntimePaths = func() (paths.Paths, error) {
			return paths.Paths{PidFilePath: filepath.Join(t.TempDir(), "daemon.pid")}, nil
		}
		processReadFile = func(string) ([]byte, error) { return nil, errors.New("read failed") }

		if err := stopDetachedProcess(); err == nil || !strings.Contains(err.Error(), "read pid file: read failed") {
			t.Fatalf("expected read error, got %v", err)
		}
	})

	t.Run("parse pid failure", func(t *testing.T) {
		origResolve := resolveRuntimePaths
		origRead := processReadFile
		defer func() {
			resolveRuntimePaths = origResolve
			processReadFile = origRead
		}()

		resolveRuntimePaths = func() (paths.Paths, error) {
			return paths.Paths{PidFilePath: filepath.Join(t.TempDir(), "daemon.pid")}, nil
		}
		processReadFile = func(string) ([]byte, error) { return []byte("not-a-pid"), nil }

		if err := stopDetachedProcess(); err == nil || !strings.Contains(err.Error(), "parse pid") {
			t.Fatalf("expected parse error, got %v", err)
		}
	})

	t.Run("find process failure", func(t *testing.T) {
		origResolve := resolveRuntimePaths
		origRead := processReadFile
		origFind := findProcessByPID
		defer func() {
			resolveRuntimePaths = origResolve
			processReadFile = origRead
			findProcessByPID = origFind
		}()

		resolveRuntimePaths = func() (paths.Paths, error) {
			return paths.Paths{PidFilePath: filepath.Join(t.TempDir(), "daemon.pid")}, nil
		}
		processReadFile = func(string) ([]byte, error) { return []byte("123"), nil }
		findProcessByPID = func(int) (*os.Process, error) { return nil, errors.New("find failed") }

		if err := stopDetachedProcess(); err == nil || !strings.Contains(err.Error(), "find process: find failed") {
			t.Fatalf("expected find error, got %v", err)
		}
	})

	t.Run("signal failure", func(t *testing.T) {
		origResolve := resolveRuntimePaths
		origRead := processReadFile
		origFind := findProcessByPID
		origSignal := signalProcess
		defer func() {
			resolveRuntimePaths = origResolve
			processReadFile = origRead
			findProcessByPID = origFind
			signalProcess = origSignal
		}()

		resolveRuntimePaths = func() (paths.Paths, error) {
			return paths.Paths{PidFilePath: filepath.Join(t.TempDir(), "daemon.pid")}, nil
		}
		processReadFile = func(string) ([]byte, error) { return []byte("123"), nil }
		findProcessByPID = os.FindProcess
		signalProcess = func(*os.Process, os.Signal) error { return errors.New("signal failed") }

		if err := stopDetachedProcess(); err == nil || !strings.Contains(err.Error(), "signal daemon: signal failed") {
			t.Fatalf("expected signal error, got %v", err)
		}
	})

	t.Run("waits for graceful exit", func(t *testing.T) {
		origResolve := resolveRuntimePaths
		origRead := processReadFile
		origFind := findProcessByPID
		origSignal := signalProcess
		origRemove := runtimeRemove
		origPoll := daemonStopPollInterval
		defer func() {
			resolveRuntimePaths = origResolve
			processReadFile = origRead
			findProcessByPID = origFind
			signalProcess = origSignal
			runtimeRemove = origRemove
			daemonStopPollInterval = origPoll
		}()

		pidPath := filepath.Join(t.TempDir(), "daemon.pid")
		resolveRuntimePaths = func() (paths.Paths, error) { return paths.Paths{PidFilePath: pidPath}, nil }
		processReadFile = func(string) ([]byte, error) { return []byte("123"), nil }
		findProcessByPID = os.FindProcess
		daemonStopPollInterval = time.Nanosecond
		probeCount := 0
		signalProcess = func(_ *os.Process, sig os.Signal) error {
			if sig == syscall.SIGTERM {
				return nil
			}
			if sig == syscall.Signal(0) {
				probeCount++
				if probeCount == 1 {
					return nil
				}
				return syscall.ESRCH
			}
			t.Fatalf("unexpected signal %v", sig)
			return nil
		}
		removed := false
		runtimeRemove = func(path string) error {
			if path == pidPath {
				removed = true
			}
			return nil
		}

		if err := stopDetachedProcess(); err != nil {
			t.Fatalf("stop detached process: %v", err)
		}
		if !removed {
			t.Fatal("expected pid file removal")
		}
	})

	t.Run("kills stubborn process", func(t *testing.T) {
		origResolve := resolveRuntimePaths
		origRead := processReadFile
		origFind := findProcessByPID
		origSignal := signalProcess
		origRemove := runtimeRemove
		origStopTimeout := daemonStopTimeout
		origKillTimeout := daemonStopKillTimeout
		origPoll := daemonStopPollInterval
		defer func() {
			resolveRuntimePaths = origResolve
			processReadFile = origRead
			findProcessByPID = origFind
			signalProcess = origSignal
			runtimeRemove = origRemove
			daemonStopTimeout = origStopTimeout
			daemonStopKillTimeout = origKillTimeout
			daemonStopPollInterval = origPoll
		}()

		pidPath := filepath.Join(t.TempDir(), "daemon.pid")
		resolveRuntimePaths = func() (paths.Paths, error) { return paths.Paths{PidFilePath: pidPath}, nil }
		processReadFile = func(string) ([]byte, error) { return []byte("123"), nil }
		findProcessByPID = os.FindProcess
		daemonStopTimeout = 0
		daemonStopKillTimeout = time.Second
		daemonStopPollInterval = time.Nanosecond
		killed := false
		signalProcess = func(_ *os.Process, sig os.Signal) error {
			switch sig {
			case syscall.SIGTERM:
				return nil
			case syscall.SIGKILL:
				killed = true
				return nil
			case syscall.Signal(0):
				if killed {
					return syscall.ESRCH
				}
				return nil
			default:
				t.Fatalf("unexpected signal %v", sig)
				return nil
			}
		}
		runtimeRemove = func(string) error { return nil }

		if err := stopDetachedProcess(); err != nil {
			t.Fatalf("stop detached process: %v", err)
		}
		if !killed {
			t.Fatal("expected SIGKILL for stubborn process")
		}
	})

	t.Run("reports timeout after kill", func(t *testing.T) {
		origResolve := resolveRuntimePaths
		origRead := processReadFile
		origFind := findProcessByPID
		origSignal := signalProcess
		origRemove := runtimeRemove
		origStopTimeout := daemonStopTimeout
		origKillTimeout := daemonStopKillTimeout
		origPoll := daemonStopPollInterval
		defer func() {
			resolveRuntimePaths = origResolve
			processReadFile = origRead
			findProcessByPID = origFind
			signalProcess = origSignal
			runtimeRemove = origRemove
			daemonStopTimeout = origStopTimeout
			daemonStopKillTimeout = origKillTimeout
			daemonStopPollInterval = origPoll
		}()

		pidPath := filepath.Join(t.TempDir(), "daemon.pid")
		resolveRuntimePaths = func() (paths.Paths, error) { return paths.Paths{PidFilePath: pidPath}, nil }
		processReadFile = func(string) ([]byte, error) { return []byte("123"), nil }
		findProcessByPID = os.FindProcess
		daemonStopTimeout = 0
		daemonStopKillTimeout = 0
		daemonStopPollInterval = time.Nanosecond
		signalProcess = func(*os.Process, os.Signal) error { return nil }
		runtimeRemove = func(string) error { return nil }

		if err := stopDetachedProcess(); err == nil || !strings.Contains(err.Error(), "timed out waiting for daemon pid 123 to exit") {
			t.Fatalf("expected timeout error, got %v", err)
		}
	})
}
