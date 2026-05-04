package gitsafe

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Cache memoizes git rev-parse --show-toplevel results across the daemon's
// lifetime. The lookup key is the (cleaned absolute path, dir stat) pair —
// path-string equality alone is not enough because the same path can be
// recreated as a different directory between calls. Entries invalidate when
// the cached top-level's .git/config mtime changes, so external git mutations
// (config edits, repo rebinds) flush the cache without a daemon restart.
//
// Worktrees and submodules — where .git is a file pointer rather than a
// directory — bypass the cache: store skips them and they fall through to
// a fresh subprocess on every call. That is correctness-first; the common
// case (a real .git/config) gets the throughput win.
type Cache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	dirInfo     os.FileInfo
	topLevel    string
	configMtime time.Time
}

func NewCache() *Cache {
	return &Cache{entries: make(map[string]cacheEntry)}
}

var defaultCache = NewCache()

var (
	cacheAbsPath  = filepath.Abs
	cacheStatPath = os.Stat
)

// TopLevelCached is TopLevel with a process-wide memoization. Hits avoid the
// 5-50ms git subprocess startup cost; entries invalidate when the directory
// is replaced (different inode) or the resolved repo's .git/config mtime
// changes. Errors are never cached.
func TopLevelCached(ctx context.Context, dir string) (string, error) {
	return defaultCache.TopLevel(ctx, dir)
}

// TopLevel resolves the git top-level for dir, returning a cached result
// when both the directory's stat and the .git/config mtime match a cached
// entry.
func (c *Cache) TopLevel(ctx context.Context, dir string) (string, error) {
	key, info, ok := cacheKeyFor(dir)
	if ok {
		if topLevel, hit := c.tryHit(key, info); hit {
			return topLevel, nil
		}
	}
	topLevel, err := TopLevel(ctx, dir)
	if err != nil {
		return "", err
	}
	if ok {
		c.store(key, info, topLevel)
	}
	return topLevel, nil
}

func cacheKeyFor(dir string) (string, os.FileInfo, bool) {
	abs, err := cacheAbsPath(dir)
	if err != nil {
		return "", nil, false
	}
	clean := filepath.Clean(abs)
	info, err := cacheStatPath(clean)
	if err != nil {
		return "", nil, false
	}
	return clean, info, true
}

func (c *Cache) tryHit(key string, info os.FileInfo) (string, bool) {
	c.mu.Lock()
	entry, ok := c.entries[key]
	c.mu.Unlock()
	if !ok {
		return "", false
	}
	if !os.SameFile(entry.dirInfo, info) {
		c.evict(key)
		return "", false
	}
	configInfo, err := cacheStatPath(filepath.Join(entry.topLevel, ".git", "config"))
	if err != nil || !configInfo.ModTime().Equal(entry.configMtime) {
		c.evict(key)
		return "", false
	}
	return entry.topLevel, true
}

func (c *Cache) store(key string, info os.FileInfo, topLevel string) {
	configInfo, err := cacheStatPath(filepath.Join(topLevel, ".git", "config"))
	if err != nil {
		return
	}
	c.mu.Lock()
	c.entries[key] = cacheEntry{
		dirInfo:     info,
		topLevel:    topLevel,
		configMtime: configInfo.ModTime(),
	}
	c.mu.Unlock()
}

func (c *Cache) evict(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}
