package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
)

// TestCheckRepoSkipsDirectoryEntriesFromEnumerator covers the info.IsDir()
// continue branch — git ls-files normally only returns files, but a custom
// enumerator (or a future submodule edge case) might yield a directory
// entry. The scanner must skip it instead of trying to ReadFile a dir.
func TestCheckRepoSkipsDirectoryEntriesFromEnumerator(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	origEnsureSession := ensureSessionAppFn
	defer func() { ensureSessionAppFn = origEnsureSession }()
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "test-session"}, nil
	}

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123secret"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "secret_01=api_token"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(projectRoot, "subdir"), 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}

	deps := defaultExecDeps()
	deps.GitLsFiles = func(context.Context, string) ([]string, error) {
		return []string{"subdir"}, nil
	}

	var out bytes.Buffer
	if err := checkRepoCommandWithDeps(context.Background(), []string{"--json", "--project-root", projectRoot}, &out, io.Discard, deps); err != nil {
		t.Fatalf("check-repo: %v", err)
	}
	if !strings.Contains(out.String(), "\"matches\":null") {
		t.Fatalf("dir-only listing must produce no matches; body=%s", out.String())
	}
}

// TestCheckRepoSurfacesReadFileError covers the readErr branch — a file
// that passes os.Stat but fails os.ReadFile (e.g., chmod 0 between the
// stat and the read). The error must propagate to the caller instead of
// being silently swallowed; otherwise an unreadable LFS object would let a
// leak slip through unnoticed.
func TestCheckRepoSurfacesReadFileError(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("chmod 0 to deny read is POSIX-only and root bypasses the mode bits")
	}
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	origEnsureSession := ensureSessionAppFn
	defer func() { ensureSessionAppFn = origEnsureSession }()
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "test-session"}, nil
	}
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123secret"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "secret_01=api_token"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("bind: %v", err)
	}
	leakPath := filepath.Join(projectRoot, "leak.txt")
	if err := os.WriteFile(leakPath, []byte("some content"), 0o600); err != nil {
		t.Fatalf("write leak: %v", err)
	}
	if out, err := run("git", "-C", projectRoot, "add", "-A"); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	if err := os.Chmod(leakPath, 0); err != nil {
		t.Fatalf("chmod 0: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(leakPath, 0o600) })

	err := checkRepoCommand(context.Background(), []string{"--json", "--project-root", projectRoot}, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected unreadable file to surface a ReadFile error")
	}
}

// TestEnumerateCheckRepoFilesSkipsDotGitInWalkDirFallback covers the .git
// SkipDir branch in the WalkDir fallback. We force gitLsFilesFn to fail in
// a real git repo so the fallback fires; without the SkipDir guard the
// scanner would descend into .git/objects and either OOM or flag pack
// blobs as leaks.
func TestEnumerateCheckRepoFilesSkipsDotGitInWalkDirFallback(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	origEnsureSession := ensureSessionAppFn
	defer func() { ensureSessionAppFn = origEnsureSession }()
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "test-session"}, nil
	}
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123secret"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "secret_01=api_token"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("bind: %v", err)
	}
	leakPath := filepath.Join(projectRoot, "leak.txt")
	if err := os.WriteFile(leakPath, []byte("abc123secret"), 0o600); err != nil {
		t.Fatalf("write leak: %v", err)
	}

	deps := defaultExecDeps()
	deps.GitLsFiles = func(context.Context, string) ([]string, error) {
		return nil, errors.New("git refused")
	}

	var out bytes.Buffer
	err := checkRepoCommandWithDeps(context.Background(), []string{"--json", "--project-root", projectRoot}, &out, io.Discard, deps)
	if err == nil {
		t.Fatal("expected leak.txt to be flagged via WalkDir fallback")
	}
	if !strings.Contains(out.String(), "leak.txt") {
		t.Fatalf("expected leak.txt match in fallback output; body=%s", out.String())
	}
	if !strings.Contains(out.String(), "\"walker\":\"walkdir\"") {
		t.Fatalf("expected walkdir walker label when ls-files fails; body=%s", out.String())
	}
}

// TestEnumerateCheckRepoFilesSurfacesRelError covers the filepath.Rel
// failure branch by mocking walkProjectDirFn to yield a relative path
// while the supplied root is absolute — filepath.Rel refuses to mix kinds.
// The fallback flag must still be true so callers report the right walker.
func TestEnumerateCheckRepoFilesSurfacesRelError(t *testing.T) {
	lockAppSeams(t)
	deps := defaultExecDeps()
	deps.WalkProjectDir = func(_ string, fn fs.WalkDirFunc) error {
		return fn("relative/path.txt", fakeDirEntry{name: "path.txt", dir: false}, nil)
	}

	files, fallback, err := enumerateCheckRepoFiles(context.Background(), "/nonexistent-abs-root", deps)
	if err == nil {
		t.Fatalf("expected filepath.Rel to fail across abs/rel mix, got files=%v", files)
	}
	if !fallback {
		t.Fatal("Rel error must report fallback=true so callers know WalkDir was attempted")
	}
}
