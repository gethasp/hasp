//go:build unix

package runtime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestStartDetachedProcessFailurePaths(t *testing.T) {
	lockRuntimeSeams(t)
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
}
