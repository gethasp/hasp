//go:build unix

package mcp

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPathLooksLikeGitRepoMCPRejectsNonRegularGitPath(t *testing.T) {
	root := t.TempDir()
	gitPath := filepath.Join(root, ".git")
	if err := syscall.Mkfifo(gitPath, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	info, err := os.Stat(gitPath)
	if err != nil {
		t.Fatalf("stat fifo .git: %v", err)
	}
	if info.IsDir() || info.Mode().IsRegular() {
		t.Fatalf("test fixture is not a non-regular .git path: mode=%v", info.Mode())
	}
	if pathLooksLikeGitRepoMCP(root) {
		t.Fatal("non-regular .git path must not look like a git repo")
	}
}
