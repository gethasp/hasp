package runtime

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionStoreOpenReturnsCurrentUserError(t *testing.T) {
	lockRuntimeSeams(t)
	origUser := currentUserFn
	defer func() { currentUserFn = origUser }()

	currentUserFn = func() (*user.User, error) {
		return nil, errors.New("lookup failed")
	}

	if _, err := NewSessionStore().Open("agent", "/tmp/project", DefaultSessionTTL, false, ""); err == nil {
		t.Fatal("expected current user failure")
	}
}

func TestSessionStoreOpenReturnsEntropyError(t *testing.T) {
	lockRuntimeSeams(t)
	origRandomRead := randomRead
	defer func() { randomRead = origRandomRead }()

	randomRead = func([]byte) (int, error) {
		return 0, errors.New("entropy failed")
	}

	if _, err := NewSessionStore().Open("agent", "/tmp/project", DefaultSessionTTL, false, ""); err == nil {
		t.Fatal("expected entropy failure")
	}
}

func TestSessionStoreOpenReturnsTokenEntropyError(t *testing.T) {
	lockRuntimeSeams(t)
	origRandomRead := randomRead
	defer func() { randomRead = origRandomRead }()

	calls := 0
	randomRead = func(buf []byte) (int, error) {
		calls++
		if calls == 2 {
			return 0, errors.New("token entropy failed")
		}
		for i := range buf {
			buf[i] = byte(i)
		}
		return len(buf), nil
	}

	if _, err := NewSessionStore().Open("agent", "/tmp/project", DefaultSessionTTL, false, ""); err == nil || !strings.Contains(err.Error(), "generate session token") {
		t.Fatalf("expected token entropy failure, got %v", err)
	}
}

func TestCanonicalProjectRootCoversEdgeCases(t *testing.T) {
	lockRuntimeSeams(t)
	origGit := gitTopLevelFn
	origAbs := filepathAbs
	defer func() {
		gitTopLevelFn = origGit
		filepathAbs = origAbs
	}()
	gitTopLevelFn = func(string) ([]byte, error) { return nil, errors.New("git disabled") }
	filepathAbs = filepath.Abs

	if got := CanonicalProjectRoot(""); got != "" {
		t.Fatalf("empty path canonical root = %q", got)
	}

	filepathAbs = func(string) (string, error) {
		return "", errors.New("abs failed")
	}
	if got := CanonicalProjectRoot("./project/../project"); got != filepath.Clean("./project/../project") {
		t.Fatalf("relative path canonical root = %q", got)
	}
	filepathAbs = filepath.Abs

	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("mkdir real dir: %v", err)
	}
	linkDir := filepath.Join(dir, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("symlink dir: %v", err)
	}
	resolvedRealDir, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatalf("resolve real dir symlinks: %v", err)
	}
	if got := CanonicalProjectRoot(linkDir); got != resolvedRealDir {
		t.Fatalf("symlink canonical root = %q, want %q", got, resolvedRealDir)
	}
}
