package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// hasp-wlkm: CanonicalProjectRoot is hit on every brokered call, and its
// final step (filepath.EvalSymlinks) walks the path with a syscall per
// component. The daemon survives across calls, so memoize the result per
// input path with FileInfo-based invalidation. These tests pin the
// contract: same input avoids a second EvalSymlinks; replacing the
// directory at the same path invalidates the cache; an EvalSymlinks
// failure is not cached.

func TestCanonicalProjectRootMemoizesEvalSymlinks(t *testing.T) {
	lockRuntimeSeams(t)
	origGit := gitTopLevelFn
	origAbs := filepathAbs
	origEval := evalSymlinksFn
	defer func() {
		gitTopLevelFn = origGit
		filepathAbs = origAbs
		evalSymlinksFn = origEval
	}()
	gitTopLevelFn = func(string) ([]byte, error) { return nil, errors.New("git disabled") }
	filepathAbs = filepath.Abs

	resetCanonicalRootCache()

	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("mkdir real: %v", err)
	}

	var calls atomic.Int32
	evalSymlinksFn = func(p string) (string, error) {
		calls.Add(1)
		return filepath.EvalSymlinks(p)
	}

	for i := 0; i < 5; i++ {
		if got := CanonicalProjectRoot(realDir); got == "" {
			t.Fatalf("CanonicalProjectRoot #%d returned empty", i)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected EvalSymlinks once across 5 lookups, got %d", got)
	}
}

func TestCanonicalProjectRootInvalidatesWhenDirectoryReplaced(t *testing.T) {
	lockRuntimeSeams(t)
	origGit := gitTopLevelFn
	origAbs := filepathAbs
	origEval := evalSymlinksFn
	defer func() {
		gitTopLevelFn = origGit
		filepathAbs = origAbs
		evalSymlinksFn = origEval
	}()
	gitTopLevelFn = func(string) ([]byte, error) { return nil, errors.New("git disabled") }
	filepathAbs = filepath.Abs

	resetCanonicalRootCache()

	parent := t.TempDir()
	target := filepath.Join(parent, "proj")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	var calls atomic.Int32
	evalSymlinksFn = func(p string) (string, error) {
		calls.Add(1)
		return filepath.EvalSymlinks(p)
	}

	CanonicalProjectRoot(target)

	if err := os.RemoveAll(target); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("recreate: %v", err)
	}

	CanonicalProjectRoot(target)

	if got := calls.Load(); got != 2 {
		t.Fatalf("expected EvalSymlinks twice after directory replace (different inode), got %d", got)
	}
}

func TestCanonicalProjectRootDoesNotCacheEvalSymlinksErrors(t *testing.T) {
	lockRuntimeSeams(t)
	origGit := gitTopLevelFn
	origAbs := filepathAbs
	origEval := evalSymlinksFn
	defer func() {
		gitTopLevelFn = origGit
		filepathAbs = origAbs
		evalSymlinksFn = origEval
	}()
	gitTopLevelFn = func(string) ([]byte, error) { return nil, errors.New("git disabled") }
	filepathAbs = filepath.Abs

	resetCanonicalRootCache()

	dir := t.TempDir()
	target := filepath.Join(dir, "proj")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	var calls atomic.Int32
	evalSymlinksFn = func(p string) (string, error) {
		calls.Add(1)
		return "", errors.New("eval failure")
	}

	CanonicalProjectRoot(target)
	CanonicalProjectRoot(target)

	if got := calls.Load(); got != 2 {
		t.Fatalf("EvalSymlinks errors must not be cached; expected 2 calls, got %d", got)
	}
}
