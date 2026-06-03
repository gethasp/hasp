package reposcan

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestScanWalkdirMatchesSkipsAndErrors(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "small.txt"), []byte("token-value"), 0o600); err != nil {
		t.Fatalf("write small: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "large.txt"), []byte("this-file-is-too-large"), 0o600); err != nil {
		t.Fatalf("write large: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatalf("mkdir git: %v", err)
	}
	deps := Deps{
		GitLsFiles: func(context.Context, string) ([]string, error) {
			return nil, errors.New("git unavailable")
		},
	}
	result, err := Scan(context.Background(), root, []store.Item{{Name: "API_TOKEN", Value: []byte("token-value")}}, 12, deps)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if result.Walker != "walkdir" {
		t.Fatalf("walker = %q", result.Walker)
	}
	if len(result.Matches) != 1 || result.Matches[0].Path != "small.txt" || result.Matches[0].ItemName != "API_TOKEN" {
		t.Fatalf("matches = %+v", result.Matches)
	}
	if len(result.Skipped) != 1 || result.Skipped[0].Path != "large.txt" || result.Skipped[0].Reason != "over_max_bytes" {
		t.Fatalf("skipped = %+v", result.Skipped)
	}

	_, err = Scan(context.Background(), root, nil, DefaultMaxBytes, Deps{
		Stat: func(string) (os.FileInfo, error) { return nil, errors.New("stat") },
	})
	if err == nil {
		t.Fatal("expected stat error")
	}
	_, err = Scan(context.Background(), root, nil, DefaultMaxBytes, Deps{
		Stat: os.Stat,
		ReadFile: func(string) ([]byte, error) {
			return nil, errors.New("read")
		},
	})
	if err == nil {
		t.Fatal("expected read error")
	}
	_, err = Scan(context.Background(), root, nil, DefaultMaxBytes, Deps{
		Stat: func(string) (os.FileInfo, error) { return nil, errors.New("no git stat") },
		WalkDir: func(string, fs.WalkDirFunc) error {
			return errors.New("enumerate")
		},
	})
	if err == nil {
		t.Fatal("expected enumerate error")
	}
}

func TestEnumerateGitAndWalkdirBranches(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatalf("mkdir git: %v", err)
	}
	files, fallback, err := Enumerate(context.Background(), root, Deps{
		GitLsFiles: func(context.Context, string) ([]string, error) {
			return []string{"tracked.txt"}, nil
		},
	})
	if err != nil || fallback || len(files) != 1 || files[0] != "tracked.txt" {
		t.Fatalf("git enumerate files=%v fallback=%v err=%v", files, fallback, err)
	}
	if WalkerLabel(false) != "git-ls-files" || WalkerLabel(true) != "walkdir" {
		t.Fatal("unexpected walker labels")
	}
	if !HitItem([]byte("abc"), store.Item{Value: []byte("secret")}, func([]byte, []byte) int { return 0 }) {
		t.Fatal("expected custom index hit")
	}
	if HitItem([]byte("abc"), store.Item{Value: []byte("secret")}, func([]byte, []byte) int { return -1 }) {
		t.Fatal("expected custom index miss")
	}
	_, _, err = Enumerate(context.Background(), root, Deps{
		Stat: func(string) (os.FileInfo, error) { return nil, errors.New("no git stat") },
		WalkDir: func(string, fs.WalkDirFunc) error {
			return errors.New("walk")
		},
	})
	if err == nil {
		t.Fatal("expected walk error")
	}
	_, _, err = Enumerate(context.Background(), root, Deps{
		Stat: func(string) (os.FileInfo, error) { return nil, errors.New("no git stat") },
		WalkDir: func(root string, fn fs.WalkDirFunc) error {
			return fn(filepath.Join(root, "bad"), nil, errors.New("walk entry"))
		},
	})
	if err == nil {
		t.Fatal("expected walk entry error")
	}
	file := filepath.Join(root, "relerr")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write relerr file: %v", err)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat relerr file: %v", err)
	}
	_, _, err = Enumerate(context.Background(), "", Deps{
		Stat: func(string) (os.FileInfo, error) { return nil, errors.New("no git stat") },
		WalkDir: func(_ string, fn fs.WalkDirFunc) error {
			return fn(file, fs.FileInfoToDirEntry(info), nil)
		},
	})
	if err == nil {
		t.Fatal("expected rel error")
	}
}

func TestScanSkipsDirectoryReturnedByGit(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatalf("mkdir git: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "subdir"), 0o700); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	result, err := Scan(context.Background(), root, nil, 0, Deps{
		GitLsFiles: func(context.Context, string) ([]string, error) {
			return []string{"subdir"}, nil
		},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if result.Walker != "git-ls-files" || len(result.Matches) != 0 || len(result.Skipped) != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestDefaultDepsGitLsFilesAndWithDefaults(t *testing.T) {
	root := t.TempDir()
	deps := DefaultDeps()
	if deps.Stat == nil || deps.ReadFile == nil || deps.WalkDir == nil || deps.GitLsFiles == nil || deps.ByteIndex == nil ||
		deps.GitStagedFiles == nil || deps.StagedBlobSize == nil || deps.ReadStagedBlob == nil {
		t.Fatalf("default deps missing function: %+v", deps)
	}
	completed := withDefaults(Deps{})
	if completed.Stat == nil || completed.ReadFile == nil || completed.WalkDir == nil || completed.GitLsFiles == nil || completed.ByteIndex == nil ||
		completed.GitStagedFiles == nil || completed.StagedBlobSize == nil || completed.ReadStagedBlob == nil {
		t.Fatalf("withDefaults missing function: %+v", completed)
	}
	if _, err := deps.GitLsFiles(context.Background(), root); err == nil {
		t.Fatal("expected git ls-files outside repo to fail")
	}
	if _, err := deps.GitStagedFiles(context.Background(), root); err == nil {
		t.Fatal("expected git staged files outside repo to fail")
	}
	if _, err := deps.StagedBlobSize(context.Background(), root, "missing.txt"); err == nil {
		t.Fatal("expected staged blob size outside repo to fail")
	}
	if _, err := deps.ReadStagedBlob(context.Background(), root, "missing.txt"); err == nil {
		t.Fatal("expected staged blob read outside repo to fail")
	}

	gitRoot := t.TempDir()
	if out, err := exec.Command("git", "-C", gitRoot, "init").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(gitRoot, "tracked.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write tracked: %v", err)
	}
	if out, err := exec.Command("git", "-C", gitRoot, "add", "tracked.txt").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(gitRoot, "untracked.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write untracked: %v", err)
	}
	files, err := deps.GitLsFiles(context.Background(), gitRoot)
	if err != nil {
		t.Fatalf("GitLsFiles: %v", err)
	}
	got := map[string]bool{}
	for _, file := range files {
		got[file] = true
	}
	if !got["tracked.txt"] || !got["untracked.txt"] {
		t.Fatalf("expected tracked and untracked files, got %v", files)
	}
	staged, err := deps.GitStagedFiles(context.Background(), gitRoot)
	if err != nil {
		t.Fatalf("GitStagedFiles: %v", err)
	}
	if len(staged) != 1 || staged[0] != "tracked.txt" {
		t.Fatalf("expected only tracked.txt staged, got %v", staged)
	}
	size, err := deps.StagedBlobSize(context.Background(), gitRoot, "tracked.txt")
	if err != nil {
		t.Fatalf("StagedBlobSize: %v", err)
	}
	if size != 1 {
		t.Fatalf("staged size = %d, want 1", size)
	}
	blob, err := deps.ReadStagedBlob(context.Background(), gitRoot, "tracked.txt")
	if err != nil {
		t.Fatalf("ReadStagedBlob: %v", err)
	}
	if string(blob) != "x" {
		t.Fatalf("staged blob = %q", blob)
	}
}
