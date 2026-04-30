package gitsafe

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// hasp-24zj: brokered calls flow through CanonicalProjectRoot, which calls
// gitsafe.TopLevel on every request. The git subprocess startup cost is
// 5-50ms per call; the daemon is long-lived, so memoizing per directory
// (with mtime-based invalidation) is straight throughput. These tests pin
// the cache contract: hits must avoid the subprocess; mtime changes and
// directory replacement must invalidate; errors must not poison the cache.

func TestCacheTopLevelReusesResultsForSameDirectory(t *testing.T) {
	repo := setupGitLikeDir(t)

	var calls atomic.Int32
	restore := stubGitSubprocess(repo, &calls)
	defer restore()

	cache := NewCache()
	for i := 0; i < 5; i++ {
		got, err := cache.TopLevel(context.Background(), repo)
		if err != nil {
			t.Fatalf("cache.TopLevel #%d: %v", i, err)
		}
		if got != repo {
			t.Fatalf("cache.TopLevel returned %q, want %q", got, repo)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected 1 git invocation across 5 lookups, got %d", got)
	}
}

func TestCacheTopLevelInvalidatesOnConfigMtimeChange(t *testing.T) {
	repo := setupGitLikeDir(t)

	var calls atomic.Int32
	restore := stubGitSubprocess(repo, &calls)
	defer restore()

	cache := NewCache()
	if _, err := cache.TopLevel(context.Background(), repo); err != nil {
		t.Fatalf("first lookup: %v", err)
	}

	configPath := filepath.Join(repo, ".git", "config")
	bumped := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(configPath, bumped, bumped); err != nil {
		t.Fatalf("chtimes %s: %v", configPath, err)
	}

	if _, err := cache.TopLevel(context.Background(), repo); err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected 2 git invocations after .git/config mtime bump, got %d", got)
	}
}

func TestCacheTopLevelInvalidatesWhenDirectoryReplaced(t *testing.T) {
	parent := t.TempDir()
	repoPath := filepath.Join(parent, "proj")
	populateGitLikeDir(t, repoPath)

	var calls atomic.Int32
	restore := stubGitSubprocess(repoPath, &calls)
	defer restore()

	cache := NewCache()
	if _, err := cache.TopLevel(context.Background(), repoPath); err != nil {
		t.Fatalf("first lookup: %v", err)
	}

	if err := os.RemoveAll(repoPath); err != nil {
		t.Fatalf("remove dir: %v", err)
	}
	populateGitLikeDir(t, repoPath)

	if _, err := cache.TopLevel(context.Background(), repoPath); err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected 2 git invocations after dir was replaced (new inode), got %d", got)
	}
}

func TestCacheTopLevelDoesNotCacheErrors(t *testing.T) {
	repo := t.TempDir()

	var calls atomic.Int32
	orig := commandContextFn
	defer func() { commandContextFn = orig }()
	commandContextFn = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calls.Add(1)
		return exec.CommandContext(ctx, "false")
	}

	cache := NewCache()
	if _, err := cache.TopLevel(context.Background(), repo); err == nil {
		t.Fatal("expected error from failing git invocation on first call")
	}
	if _, err := cache.TopLevel(context.Background(), repo); err == nil {
		t.Fatal("expected error on second call too — error path must not be cached")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("error path must run the subprocess each time; got %d invocations (want 2)", got)
	}
}

func TestTopLevelCachedUsesDefaultCache(t *testing.T) {
	repo := setupGitLikeDir(t)
	var calls atomic.Int32
	restoreGit := stubGitSubprocess(repo, &calls)
	defer restoreGit()
	origCache := defaultCache
	defaultCache = NewCache()
	defer func() { defaultCache = origCache }()

	for i := 0; i < 2; i++ {
		got, err := TopLevelCached(context.Background(), repo)
		if err != nil {
			t.Fatalf("TopLevelCached #%d: %v", i, err)
		}
		if got != repo {
			t.Fatalf("TopLevelCached = %q, want %q", got, repo)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected one git invocation, got %d", got)
	}
}

func TestCacheKeyForFailuresAndStoreWithoutConfig(t *testing.T) {
	origAbs := cacheAbsPath
	origStat := cacheStatPath
	defer func() {
		cacheAbsPath = origAbs
		cacheStatPath = origStat
	}()

	cacheAbsPath = func(string) (string, error) { return "", errors.New("abs") }
	if _, _, ok := cacheKeyFor("x"); ok {
		t.Fatal("cacheKeyFor should reject abs errors")
	}

	cacheAbsPath = origAbs
	cacheStatPath = func(string) (os.FileInfo, error) { return nil, errors.New("stat") }
	if _, _, ok := cacheKeyFor("x"); ok {
		t.Fatal("cacheKeyFor should reject stat errors")
	}

	cacheStatPath = origStat
	dir := t.TempDir()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	cache := NewCache()
	cache.store("key", info, filepath.Join(dir, "no-config"))
	if _, ok := cache.entries["key"]; ok {
		t.Fatal("store should skip entries without .git/config")
	}
}

func setupGitLikeDir(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	populateGitLikeDir(t, repo)
	return repo
}

func populateGitLikeDir(t *testing.T, repo string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir %s/.git: %v", repo, err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatalf("write .git/config: %v", err)
	}
}

func stubGitSubprocess(topLevel string, calls *atomic.Int32) func() {
	orig := commandContextFn
	commandContextFn = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calls.Add(1)
		return exec.CommandContext(ctx, "echo", topLevel)
	}
	return func() { commandContextFn = orig }
}
