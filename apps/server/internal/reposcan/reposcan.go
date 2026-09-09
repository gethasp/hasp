package reposcan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/gitsafe"
	"github.com/gethasp/hasp/apps/server/internal/redactor"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

const DefaultMaxFileBytes int64 = 4 << 20

// DefaultMaxBytes is the canonical scanner cap. Keep the older
// DefaultMaxFileBytes name as a compatibility alias for existing tests and
// call sites.
const DefaultMaxBytes = DefaultMaxFileBytes

type Deps struct {
	Stat            func(path string) (os.FileInfo, error)
	ReadFile        func(path string) ([]byte, error)
	WalkDir         func(root string, fn fs.WalkDirFunc) error
	GitLsFiles      func(ctx context.Context, root string) ([]string, error)
	GitDeletedFiles func(ctx context.Context, root string) ([]string, error)
	ByteIndex       func(data []byte, needle []byte) int
	// Staged-content scanning (pre-commit gate): these read the INDEX (stage 0)
	// blobs rather than the working tree, so a secret that is staged then
	// overwritten in the working tree cannot slip past the gate.
	GitStagedFiles func(ctx context.Context, root string) ([]string, error)
	StagedBlobSize func(ctx context.Context, root, rel string) (int64, error)
	ReadStagedBlob func(ctx context.Context, root, rel string) ([]byte, error)
}

type Match struct {
	Path     string `json:"path"`
	ItemName string `json:"item_name"`
}

type Skipped struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Reason string `json:"reason"`
}

type Issue struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

type Result struct {
	Stats    Stats     `json:"stats"`
	Complete bool      `json:"complete"`
	Deleted  []string  `json:"deleted,omitempty"`
	Issues   []Issue   `json:"issues,omitempty"`
	Matches  []Match   `json:"matches"`
	Skipped  []Skipped `json:"skipped"`
	Walker   string    `json:"walker"`
}

type compiledItem struct {
	name    string
	needles [][]byte
}

func DefaultDeps() Deps {
	return Deps{
		Stat:     os.Stat,
		ReadFile: os.ReadFile,
		WalkDir:  filepath.WalkDir,
		GitLsFiles: func(ctx context.Context, root string) ([]string, error) {
			cmd := gitsafe.BuildCommand(ctx, root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
			out, err := cmd.Output()
			if err != nil {
				return nil, err
			}
			return splitGitPaths(out), nil
		},
		GitDeletedFiles: func(ctx context.Context, root string) ([]string, error) {
			cmd := gitsafe.BuildCommand(ctx, root, "ls-files", "--deleted", "-z")
			out, err := cmd.Output()
			if err != nil {
				return nil, err
			}
			return splitGitPaths(out), nil
		},
		ByteIndex: bytes.Index,
		GitStagedFiles: func(ctx context.Context, root string) ([]string, error) {
			// Added/Copied/Modified/Renamed entries in the index — i.e. exactly the
			// file content that the pending commit will contain.
			cmd := gitsafe.BuildIndexCommand(ctx, root, "diff", "--cached", "--no-ext-diff", "--no-textconv", "--name-only", "--diff-filter=ACMRTU", "-z")
			out, err := cmd.Output()
			if err != nil {
				return nil, err
			}
			return splitGitPaths(out), nil
		},
		StagedBlobSize: func(ctx context.Context, root, rel string) (int64, error) {
			cmd := gitsafe.BuildIndexCommand(ctx, root, "cat-file", "-s", ":"+rel)
			out, err := cmd.Output()
			if err != nil {
				return 0, err
			}
			return strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		},
		ReadStagedBlob: func(ctx context.Context, root, rel string) ([]byte, error) {
			cmd := gitsafe.BuildIndexCommand(ctx, root, "cat-file", "blob", ":"+rel)
			return cmd.Output()
		},
	}
}

func splitGitPaths(data []byte) []string {
	parts := bytes.Split(data, []byte{0})
	files := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) > 0 {
			files = append(files, string(part))
		}
	}
	return files
}

func (r *Result) addIssue(path, reason string, err error) {
	r.Complete = false
	r.Issues = append(r.Issues, Issue{Path: path, Reason: reason, Detail: err.Error()})
}

func Scan(ctx context.Context, root string, items []store.Item, maxBytes int64, deps Deps) (result Result, resultErr error) {
	defer result.finish(time.Now())
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	deps = withDefaults(deps)
	enumStart := time.Now()
	files, fallback, enumErr := Enumerate(ctx, root, deps)
	result = Result{Walker: WalkerLabel(fallback), Complete: true}
	result.Stats.EnumerationMS = elapsedMS(enumStart)
	result.Stats.SourcesEnumerated = len(files)
	var failures []error
	if enumErr != nil {
		result.addIssue(".", "enumeration_failed", enumErr)
		failures = append(failures, enumErr)
	}
	compiled := result.compile(items)
	var deleted map[string]bool
	var deletionErr error
	for _, rel := range files {
		if err := ctx.Err(); err != nil {
			result.addIssue(rel, "cancelled", err)
			failures = append(failures, err)
			break
		}
		abs := filepath.Join(root, rel)
		info, statErr := measure(&result.Stats.ReadMS, func() (os.FileInfo, error) { return deps.Stat(abs) })
		if statErr != nil {
			if !fallback && errors.Is(statErr, os.ErrNotExist) {
				if deleted == nil {
					deleted = make(map[string]bool)
					var paths []string
					paths, deletionErr = deps.GitDeletedFiles(ctx, root)
					for _, path := range paths {
						deleted[path] = true
					}
				}
				if deletionErr == nil && deleted[rel] {
					result.Deleted = append(result.Deleted, rel)
					continue
				}
			}
			result.addIssue(rel, "stat_failed", statErr)
			failures = append(failures, fmt.Errorf("%s: %w", rel, statErr))
			continue
		}
		if info.IsDir() {
			continue
		}
		if info.Size() > maxBytes {
			result.Complete = false
			result.Skipped = append(result.Skipped, Skipped{Path: rel, Size: info.Size(), Reason: "over_max_bytes"})
			continue
		}
		data, readErr := measure(&result.Stats.ReadMS, func() ([]byte, error) { return deps.ReadFile(abs) })
		if readErr != nil {
			result.addIssue(rel, "read_failed", readErr)
			failures = append(failures, fmt.Errorf("%s: %w", rel, readErr))
			continue
		}
		if int64(len(data)) > maxBytes {
			result.Complete = false
			result.Skipped = append(result.Skipped, Skipped{Path: rel, Size: int64(len(data)), Reason: "over_max_bytes"})
			continue
		}
		result.match(rel, data, compiled, deps.ByteIndex)
	}
	return result, errors.Join(failures...)
}

// ScanStaged reads index content, including Git's temporary index for a partial
// commit. Read failures retain other matches and still fail the gate closed.
// Empty staged dependencies select a shared Git object reader. Explicit staged
// reader overrides retain the per-path interface for fault injection.
func ScanStaged(ctx context.Context, root string, items []store.Item, maxBytes int64, deps Deps) (result Result, resultErr error) {
	if deps.GitStagedFiles == nil && deps.StagedBlobSize == nil && deps.ReadStagedBlob == nil {
		return scanStagedObjects(ctx, root, items, maxBytes, deps.ByteIndex)
	}
	defer result.finish(time.Now())
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	deps = withDefaults(deps)
	result = Result{Walker: "git-staged", Complete: true}
	enumStart := time.Now()
	files, enumErr := deps.GitStagedFiles(ctx, root)
	result.Stats.EnumerationMS = elapsedMS(enumStart)
	result.Stats.SourcesEnumerated = len(files)
	var failures []error
	if enumErr != nil {
		result.addIssue(".", "enumeration_failed", enumErr)
		failures = append(failures, enumErr)
	}
	compiled := result.compile(items)
	for _, rel := range files {
		if err := ctx.Err(); err != nil {
			result.addIssue(rel, "cancelled", err)
			failures = append(failures, err)
			break
		}
		size, sizeErr := measure(&result.Stats.ReadMS, func() (int64, error) { return deps.StagedBlobSize(ctx, root, rel) })
		if sizeErr != nil {
			result.addIssue(rel, "index_read_failed", sizeErr)
			failures = append(failures, fmt.Errorf("%s: %w", rel, sizeErr))
			continue
		}
		if size > maxBytes {
			result.Complete = false
			result.Skipped = append(result.Skipped, Skipped{Path: rel, Size: size, Reason: "over_max_bytes"})
			continue
		}
		data, readErr := measure(&result.Stats.ReadMS, func() ([]byte, error) { return deps.ReadStagedBlob(ctx, root, rel) })
		if readErr != nil {
			result.addIssue(rel, "index_read_failed", readErr)
			failures = append(failures, fmt.Errorf("%s: %w", rel, readErr))
			continue
		}
		if int64(len(data)) > maxBytes {
			result.Complete = false
			result.Skipped = append(result.Skipped, Skipped{Path: rel, Size: int64(len(data)), Reason: "over_max_bytes"})
			continue
		}
		result.match(rel, data, compiled, deps.ByteIndex)
	}
	return result, errors.Join(failures...)
}

func WalkerLabel(fallback bool) string {
	if fallback {
		return "walkdir"
	}
	return "git-ls-files"
}

func HitItem(data []byte, item store.Item, byteIndex ...func([]byte, []byte) int) bool {
	if !item.Confidential() {
		return false
	}
	return hitNeedles(data, redactor.Needles(item.Value), byteIndex...)
}

func compileItems(items []store.Item) []compiledItem {
	compiled := make([]compiledItem, 0, len(items))
	for _, item := range items {
		if !item.Confidential() {
			continue
		}
		needles := redactor.Needles(item.Value)
		if len(needles) == 0 {
			continue
		}
		compiled = append(compiled, compiledItem{name: item.Name, needles: needles})
	}
	return compiled
}

func hitNeedles(data []byte, needles [][]byte, byteIndex ...func([]byte, []byte) int) bool {
	index := bytes.Index
	if len(byteIndex) > 0 && byteIndex[0] != nil {
		index = byteIndex[0]
	}
	for _, needle := range needles {
		if index(data, needle) >= 0 {
			return true
		}
	}
	return false
}

func Enumerate(ctx context.Context, root string, deps Deps) ([]string, bool, error) {
	deps = withDefaults(deps)
	if _, err := deps.Stat(filepath.Join(root, ".git")); err == nil {
		files, gitErr := deps.GitLsFiles(ctx, root)
		if gitErr == nil {
			return files, false, nil
		}
	}
	var files []string
	var walkFailures []error
	err := deps.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			walkFailures = append(walkFailures, fmt.Errorf("%s: %w", path, walkErr))
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		walkFailures = append(walkFailures, err)
	}
	return files, true, errors.Join(walkFailures...)
}

func withDefaults(deps Deps) Deps {
	defaults := DefaultDeps()
	if deps.Stat == nil {
		deps.Stat = defaults.Stat
	}
	if deps.ReadFile == nil {
		deps.ReadFile = defaults.ReadFile
	}
	if deps.WalkDir == nil {
		deps.WalkDir = defaults.WalkDir
	}
	if deps.GitLsFiles == nil {
		deps.GitLsFiles = defaults.GitLsFiles
	}
	if deps.GitDeletedFiles == nil {
		deps.GitDeletedFiles = defaults.GitDeletedFiles
	}
	if deps.ByteIndex == nil {
		deps.ByteIndex = defaults.ByteIndex
	}
	if deps.GitStagedFiles == nil {
		deps.GitStagedFiles = defaults.GitStagedFiles
	}
	if deps.StagedBlobSize == nil {
		deps.StagedBlobSize = defaults.StagedBlobSize
	}
	if deps.ReadStagedBlob == nil {
		deps.ReadStagedBlob = defaults.ReadStagedBlob
	}
	return deps
}
