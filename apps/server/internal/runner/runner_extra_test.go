package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

type fakeInjectedTempFile struct {
	name     string
	chmodErr error
	writeErr error
	closeErr error
}

func (f *fakeInjectedTempFile) Name() string              { return f.name }
func (f *fakeInjectedTempFile) Chmod(os.FileMode) error   { return f.chmodErr }
func (f *fakeInjectedTempFile) Write([]byte) (int, error) { return 0, f.writeErr }
func (f *fakeInjectedTempFile) Close() error              { return f.closeErr }

func TestExecuteCommandFailureAndMissingCommand(t *testing.T) {
	if _, err := Execute(context.Background(), Input{}); err == nil {
		t.Fatal("expected missing command error")
	}
	result, err := Execute(context.Background(), Input{Command: []string{"sh", "-c", "exit 7"}})
	if err != nil {
		t.Fatalf("execute failure command: %v", err)
	}
	if result.ExitCode != 7 {
		t.Fatalf("exit code = %d", result.ExitCode)
	}
	if _, err := Execute(context.Background(), Input{Command: []string{"definitely-not-a-command"}}); err == nil || !strings.Contains(err.Error(), "executable file not found") {
		t.Fatalf("expected command-not-found error, got %v", err)
	}
}

func TestExecuteCapturesEnvAndStderr(t *testing.T) {
	result, err := Execute(context.Background(), Input{
		Command: []string{"sh", "-c", "printf '%s' \"$FLAG\"; printf '%s' error >&2"},
		Env:     map[string]string{"FLAG": "value"},
	})
	if err != nil {
		t.Fatalf("execute command: %v", err)
	}
	if string(result.Stdout) != "value" || string(result.Stderr) != "error" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestEnsureInjectionDirAndCleanupHelpers(t *testing.T) {
	if err := cleanupStaleInjectedFiles(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected cleanup to fail for missing inject dir")
	}

	baseDir := t.TempDir()
	blocker := filepath.Join(baseDir, "blocked")
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if err := ensureInjectionDir(filepath.Join(blocker, "inject"), baseDir); err == nil {
		t.Fatal("expected ensureInjectionDir to fail when parent is a file")
	}

	injectDir := filepath.Join(baseDir, "inject")
	if err := os.MkdirAll(filepath.Join(injectDir, "nested"), 0o700); err != nil {
		t.Fatalf("mkdir inject dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(injectDir, "other-file"), []byte("keep"), 0o600); err != nil {
		t.Fatalf("write other file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(injectDir, "hasp-stale"), []byte("remove"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}
	if err := cleanupStaleInjectedFiles(injectDir); err != nil {
		t.Fatalf("cleanup stale files: %v", err)
	}
	if _, err := os.Stat(filepath.Join(injectDir, "hasp-stale")); !os.IsNotExist(err) {
		t.Fatalf("expected stale file removal, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(injectDir, "other-file")); err != nil {
		t.Fatalf("expected unrelated file to remain, got %v", err)
	}
}

func TestEnsureInjectionDirAndCleanupCoverFilesystemErrorBranches(t *testing.T) {
	lockRunnerSeams(t)
	origLstat := lstatInjectionPath
	origMkdir := mkdirAllInjection
	origReadDir := readInjectionDir
	origRemove := removeInjectedPath
	defer func() {
		lstatInjectionPath = origLstat
		mkdirAllInjection = origMkdir
		readInjectionDir = origReadDir
		removeInjectedPath = origRemove
	}()

	lstatInjectionPath = func(string) (os.FileInfo, error) { return nil, errors.New("lstat fail") }
	if err := ensureInjectionDir("/tmp/hasp-inject", "/tmp"); err == nil || !strings.Contains(err.Error(), "stat injection dir") {
		t.Fatalf("expected lstat failure, got %v", err)
	}

	lstatInjectionPath = origLstat
	mkdirAllInjection = func(string, os.FileMode) error { return errors.New("mkdir fail") }
	baseDir := t.TempDir()
	if err := ensureInjectionDir(filepath.Join(baseDir, "inject"), baseDir); err == nil || !strings.Contains(err.Error(), "create injection dir") {
		t.Fatalf("expected mkdir failure, got %v", err)
	}

	tempDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tempDir, "hasp-file"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}
	readInjectionDir = func(string) ([]os.DirEntry, error) { return origReadDir(tempDir) }
	removeInjectedPath = func(string) error { return errors.New("remove fail") }
	if err := cleanupStaleInjectedFiles(tempDir); err == nil || !strings.Contains(err.Error(), "cleanup stale injected file") {
		t.Fatalf("expected cleanup remove failure, got %v", err)
	}

	removeInjectedPath = func(string) error { return os.ErrNotExist }
	if err := cleanupStaleInjectedFiles(tempDir); err != nil {
		t.Fatalf("expected not-exist cleanup to be ignored, got %v", err)
	}
}

func TestWriteInjectedFileFailurePaths(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if _, err := writeInjectedFile(blocker, "", "CERT_PATH", []byte("abc")); err == nil {
		t.Fatal("expected create temp failure")
	}

	injectDir := t.TempDir()
	if _, err := writeInjectedFile(injectDir, injectDir, "CERT_PATH", []byte("abc")); err == nil || !strings.Contains(err.Error(), "outside the project root") {
		t.Fatalf("expected safe injection dir refusal, got %v", err)
	}
}

func TestWriteInjectedFileCoversAbsChmodWriteAndCloseFailures(t *testing.T) {
	lockRunnerSeams(t)
	origAbs := runnerAbsPath
	origCreate := createTempFile
	defer func() {
		runnerAbsPath = origAbs
		createTempFile = origCreate
	}()

	runnerAbsPath = func(path string) (string, error) {
		if path == "bad-project" {
			return "", errors.New("abs project fail")
		}
		if path == "bad-inject" {
			return "", errors.New("abs inject fail")
		}
		return filepath.Clean(path), nil
	}
	if _, err := writeInjectedFile("/tmp/inject", "bad-project", "CERT_PATH", []byte("abc")); err == nil || !strings.Contains(err.Error(), "resolve project root") {
		t.Fatalf("expected project root abs failure, got %v", err)
	}
	if _, err := writeInjectedFile("bad-inject", "/tmp/project", "CERT_PATH", []byte("abc")); err == nil || !strings.Contains(err.Error(), "resolve injection dir") {
		t.Fatalf("expected injection dir abs failure, got %v", err)
	}

	createTempFile = func(string, string) (injectedTempFile, error) {
		return &fakeInjectedTempFile{name: filepath.Join(t.TempDir(), "temp"), chmodErr: errors.New("chmod fail")}, nil
	}
	if _, err := writeInjectedFile(t.TempDir(), "", "CERT_PATH", []byte("abc")); err == nil || !strings.Contains(err.Error(), "chmod injected file") {
		t.Fatalf("expected chmod failure, got %v", err)
	}

	createTempFile = func(string, string) (injectedTempFile, error) {
		return &fakeInjectedTempFile{name: filepath.Join(t.TempDir(), "temp"), writeErr: errors.New("write fail")}, nil
	}
	if _, err := writeInjectedFile(t.TempDir(), "", "CERT_PATH", []byte("abc")); err == nil || !strings.Contains(err.Error(), "write injected file") {
		t.Fatalf("expected write failure, got %v", err)
	}

	createTempFile = func(string, string) (injectedTempFile, error) {
		return &fakeInjectedTempFile{name: filepath.Join(t.TempDir(), "temp"), closeErr: errors.New("close fail")}, nil
	}
	if _, err := writeInjectedFile(t.TempDir(), "", "CERT_PATH", []byte("abc")); err == nil || !strings.Contains(err.Error(), "close injected file") {
		t.Fatalf("expected close failure, got %v", err)
	}
}

func TestExecutePropagatesPathResolutionFailure(t *testing.T) {
	lockRunnerSeams(t)
	origResolve := resolveRunnerPaths
	defer func() { resolveRunnerPaths = origResolve }()
	resolveRunnerPaths = func() (paths.Paths, error) {
		return paths.Paths{}, errors.New("resolve fail")
	}
	if _, err := Execute(context.Background(), Input{Command: []string{"true"}}); err == nil || !strings.Contains(err.Error(), "resolve fail") {
		t.Fatalf("expected resolve paths failure, got %v", err)
	}
}

func TestExecutePropagatesCleanupFailureAndEnsureInjectionDirRootBreak(t *testing.T) {
	lockRunnerSeams(t)
	origResolve := resolveRunnerPaths
	origReadDir := readInjectionDir
	defer func() {
		resolveRunnerPaths = origResolve
		readInjectionDir = origReadDir
	}()

	homeDir := t.TempDir()
	resolveRunnerPaths = func() (paths.Paths, error) {
		return paths.Paths{HomeDir: homeDir, RuntimeDir: filepath.Join(homeDir, "runtime")}, nil
	}
	readInjectionDir = func(string) ([]os.DirEntry, error) { return nil, errors.New("cleanup fail") }
	if _, err := Execute(context.Background(), Input{Command: []string{"true"}}); err == nil || !strings.Contains(err.Error(), "cleanup fail") {
		t.Fatalf("expected cleanup failure, got %v", err)
	}

	if err := ensureInjectionDir("/", filepath.Join(t.TempDir(), "stop")); err != nil {
		t.Fatalf("expected ensureInjectionDir root break to succeed, got %v", err)
	}
}
