package reposcan

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestScanTrackedDeletionPreservesOtherMatches(t *testing.T) {
	root := newOutgoingRepo(t, "sha1")
	outgoingCommit(t, root, "deleted.txt", "safe", "base")
	if err := os.Remove(filepath.Join(root, "deleted.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "leak.txt"), []byte("synthetic-scan-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Scan(context.Background(), root, []store.Item{{Name: "scan_token", Value: []byte("synthetic-scan-token")}}, 0, Deps{})
	if err != nil || !result.Complete || len(result.Deleted) != 1 || result.Deleted[0] != "deleted.txt" || len(result.Matches) != 1 || result.Matches[0].Path != "leak.txt" {
		t.Fatalf("tracked deletion lost scan result: %+v, %v", result, err)
	}
}

func TestScanReadFailureRetainsMatchesBeforeAndAfterFailure(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic-scan-token"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	failure := errors.New("fixture read failure")
	result, err := Scan(context.Background(), root, []store.Item{{Name: "scan_token", Value: []byte("synthetic-scan-token")}}, 0, Deps{ReadFile: func(path string) ([]byte, error) {
		if filepath.Base(path) == "b.txt" {
			return nil, failure
		}
		return os.ReadFile(path)
	}})
	if !errors.Is(err, failure) || result.Complete || len(result.Issues) != 1 || result.Issues[0].Path != "b.txt" || len(result.Matches) != 2 || result.Matches[0].Path != "a.txt" || result.Matches[1].Path != "c.txt" {
		t.Fatalf("I/O failure lost readable matches: %+v, %v", result, err)
	}
}

func TestScanPreservesWhitespacePathsInBothModes(t *testing.T) {
	root := newOutgoingRepo(t, "sha1")
	path := " leading\ntrailing "
	if err := os.WriteFile(filepath.Join(root, path), []byte("synthetic-scan-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	outgoingGit(t, root, "add", "--", path)
	for _, scan := range []func(context.Context, string, []store.Item, int64, Deps) (Result, error){Scan, ScanStaged} {
		result, err := scan(context.Background(), root, []store.Item{{Name: "scan_token", Value: []byte("synthetic-scan-token")}}, 0, Deps{})
		if err != nil || len(result.Matches) != 1 || result.Matches[0].Path != path {
			t.Fatalf("whitespace path corrupted: %+v, %v", result, err)
		}
	}
}

func TestScanRetainsWalkedFilesAfterEnumerationFailure(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "leak")
	if err := os.WriteFile(path, []byte("synthetic-scan-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Scan(context.Background(), root, []store.Item{{Name: "scan_token", Value: []byte("synthetic-scan-token")}}, 0, Deps{WalkDir: func(root string, fn fs.WalkDirFunc) error {
		if err := fn(path, fs.FileInfoToDirEntry(info), nil); err != nil {
			return err
		}
		return errors.New("fixture enumeration failure")
	}})
	if err == nil || !strings.Contains(err.Error(), "enumeration") || result.Complete || len(result.Issues) != 1 || len(result.Matches) != 1 {
		t.Fatalf("enumeration lost visited files: %+v, %v", result, err)
	}
}

func TestScanMissingUntrackedAndDanglingSymlinkFailClosed(t *testing.T) {
	root := newOutgoingRepo(t, "sha1")
	if err := os.Symlink("missing-target", filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	outgoingGit(t, root, "add", "dangling")
	for _, path := range []string{"dangling", "vanished-untracked"} {
		result, err := Scan(context.Background(), root, nil, 0, Deps{GitLsFiles: func(context.Context, string) ([]string, error) { return []string{path}, nil }})
		if err == nil || result.Complete || len(result.Deleted) != 0 || len(result.Issues) != 1 {
			t.Fatalf("missing content incorrectly treated as tracked deletion: %+v, %v", result, err)
		}
	}
}

func TestScanStagedPartialReadRetainsOtherMatches(t *testing.T) {
	root := newOutgoingRepo(t, "sha1")
	for _, path := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte("synthetic-scan-token"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outgoingGit(t, root, "add", ".")
	failure := errors.New("fixture index failure")
	read := DefaultDeps().ReadStagedBlob
	result, err := ScanStaged(context.Background(), root, []store.Item{{Name: "scan_token", Value: []byte("synthetic-scan-token")}}, 0, Deps{ReadStagedBlob: func(ctx context.Context, root, path string) ([]byte, error) {
		if path == "b" {
			return nil, failure
		}
		return read(ctx, root, path)
	}})
	if !errors.Is(err, failure) || result.Complete || len(result.Matches) != 2 || len(result.Issues) != 1 || result.Issues[0].Reason != "index_read_failed" {
		t.Fatalf("partial index read lost evidence: %+v, %v", result, err)
	}
}

func TestScanStagedUsesActiveTemporaryIndex(t *testing.T) {
	root := newOutgoingRepo(t, "sha1")
	outgoingCommit(t, root, "token", "safe", "base")
	indexData, err := os.ReadFile(filepath.Join(root, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(t.TempDir(), "alternate-index")
	if err := os.WriteFile(index, indexData, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_INDEX_FILE", index)
	if err := os.WriteFile(filepath.Join(root, "token"), []byte("synthetic-scan-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	outgoingGit(t, root, "add", "token")
	if err := os.WriteFile(filepath.Join(root, "token"), []byte("safe again"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := ScanStaged(context.Background(), root, []store.Item{{Name: "scan_token", Value: []byte("synthetic-scan-token")}}, 0, Deps{})
	if err != nil || !result.Complete || len(result.Matches) != 1 {
		t.Fatalf("active index was ignored: %+v, %v", result, err)
	}
	t.Setenv("GIT_INDEX_FILE", "")
	result, err = ScanStaged(context.Background(), root, []store.Item{{Name: "scan_token", Value: []byte("synthetic-scan-token")}}, 0, Deps{})
	if err != nil || len(result.Matches) != 0 {
		t.Fatalf("default index unexpectedly changed: %+v, %v", result, err)
	}
}
