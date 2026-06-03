package reposcan

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	Stat       func(path string) (os.FileInfo, error)
	ReadFile   func(path string) ([]byte, error)
	WalkDir    func(root string, fn fs.WalkDirFunc) error
	GitLsFiles func(ctx context.Context, root string) ([]string, error)
	ByteIndex  func(data []byte, needle []byte) int
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

type Result struct {
	Matches []Match   `json:"matches"`
	Skipped []Skipped `json:"skipped"`
	Walker  string    `json:"walker"`
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
			parts := bytes.Split(out, []byte{0})
			files := make([]string, 0, len(parts))
			for _, part := range parts {
				trimmed := strings.TrimSpace(string(part))
				if trimmed != "" {
					files = append(files, trimmed)
				}
			}
			return files, nil
		},
		ByteIndex: bytes.Index,
		GitStagedFiles: func(ctx context.Context, root string) ([]string, error) {
			// Added/Copied/Modified/Renamed entries in the index — i.e. exactly the
			// file content that the pending commit will contain.
			cmd := gitsafe.BuildCommand(ctx, root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
			out, err := cmd.Output()
			if err != nil {
				return nil, err
			}
			parts := bytes.Split(out, []byte{0})
			files := make([]string, 0, len(parts))
			for _, part := range parts {
				trimmed := strings.TrimSpace(string(part))
				if trimmed != "" {
					files = append(files, trimmed)
				}
			}
			return files, nil
		},
		StagedBlobSize: func(ctx context.Context, root, rel string) (int64, error) {
			cmd := gitsafe.BuildCommand(ctx, root, "cat-file", "-s", ":"+rel)
			out, err := cmd.Output()
			if err != nil {
				return 0, err
			}
			return strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		},
		ReadStagedBlob: func(ctx context.Context, root, rel string) ([]byte, error) {
			cmd := gitsafe.BuildCommand(ctx, root, "cat-file", "blob", ":"+rel)
			return cmd.Output()
		},
	}
}

func Scan(ctx context.Context, root string, items []store.Item, maxBytes int64, deps Deps) (Result, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	deps = withDefaults(deps)
	files, fallback, err := Enumerate(ctx, root, deps)
	if err != nil {
		return Result{}, err
	}
	result := Result{Walker: WalkerLabel(fallback)}
	compiled := compileItems(items)
	for _, rel := range files {
		abs := filepath.Join(root, rel)
		info, statErr := deps.Stat(abs)
		if statErr != nil {
			return Result{}, statErr
		}
		if info.IsDir() {
			continue
		}
		if info.Size() > maxBytes {
			result.Skipped = append(result.Skipped, Skipped{Path: rel, Size: info.Size(), Reason: "over_max_bytes"})
			continue
		}
		data, readErr := deps.ReadFile(abs)
		if readErr != nil {
			return Result{}, readErr
		}
		for _, item := range compiled {
			if hitNeedles(data, item.needles, deps.ByteIndex) {
				result.Matches = append(result.Matches, Match{Path: rel, ItemName: item.name})
			}
		}
	}
	return result, nil
}

// ScanStaged scans the staged INDEX content (stage 0 blobs) rather than the
// working tree. This is the correct source for a pre-commit gate: a secret that
// is `git add`-ed and then overwritten in the working tree is still in the
// commit, and Scan (working-tree) would miss it. Reads fail closed.
func ScanStaged(ctx context.Context, root string, items []store.Item, maxBytes int64, deps Deps) (Result, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	deps = withDefaults(deps)
	files, err := deps.GitStagedFiles(ctx, root)
	if err != nil {
		return Result{}, err
	}
	result := Result{Walker: "git-staged"}
	compiled := compileItems(items)
	for _, rel := range files {
		size, sizeErr := deps.StagedBlobSize(ctx, root, rel)
		if sizeErr != nil {
			return Result{}, sizeErr
		}
		if size > maxBytes {
			result.Skipped = append(result.Skipped, Skipped{Path: rel, Size: size, Reason: "over_max_bytes"})
			continue
		}
		data, readErr := deps.ReadStagedBlob(ctx, root, rel)
		if readErr != nil {
			return Result{}, readErr
		}
		for _, item := range compiled {
			if hitNeedles(data, item.needles, deps.ByteIndex) {
				result.Matches = append(result.Matches, Match{Path: rel, ItemName: item.name})
			}
		}
	}
	return result, nil
}

func WalkerLabel(fallback bool) string {
	if fallback {
		return "walkdir"
	}
	return "git-ls-files"
}

func HitItem(data []byte, item store.Item, byteIndex ...func([]byte, []byte) int) bool {
	return hitNeedles(data, redactor.Needles(item.Value), byteIndex...)
}

func compileItems(items []store.Item) []compiledItem {
	compiled := make([]compiledItem, 0, len(items))
	for _, item := range items {
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
	err := deps.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
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
		return nil, true, err
	}
	return files, true, nil
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
