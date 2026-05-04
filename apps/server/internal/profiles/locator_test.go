package profiles

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCatalogDirEnvOverrideAndErrors(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(envProfilesDir, dir)
	got, err := CatalogDir()
	if err != nil {
		t.Fatalf("catalog dir override: %v", err)
	}
	if got != dir {
		t.Fatalf("catalog dir = %q, want %q", got, dir)
	}

	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv(envProfilesDir, missing)
	if _, err := CatalogDir(); err == nil {
		t.Fatal("expected missing override directory error")
	}

	filePath := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	t.Setenv(envProfilesDir, filePath)
	if _, err := CatalogDir(); err == nil {
		t.Fatal("expected non-directory override error")
	}
}

func TestResolveRepoPathAndHelpers(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "absolute")
	if got, err := ResolveRepoPath(abs); err != nil || got != abs {
		t.Fatalf("resolve absolute path = %q err=%v", got, err)
	}

	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	expectedDocs := filepath.Join(root, "docs", "agent-profiles", "claude-code.md")
	gotDocs, err := ResolveRepoPath("docs/agent-profiles/claude-code.md")
	if err != nil || gotDocs != expectedDocs {
		t.Fatalf("resolve repo docs path = %q err=%v", gotDocs, err)
	}

	if !findBenchmarkFunction("./internal/mcp", "BenchmarkToolsList") {
		t.Fatal("expected benchmark function lookup to succeed")
	}
	if findBenchmarkFunction("./internal/mcp", "BenchmarkDoesNotExist") {
		t.Fatal("expected missing benchmark function lookup to fail")
	}
	if !findEvalTest("TestMCPEndToEndEval") {
		t.Fatal("expected eval test lookup to succeed")
	}
	if findEvalTest("TestEvalDoesNotExist") {
		t.Fatal("expected missing eval test lookup to fail")
	}
}

func TestCatalogDirDefaultAndResolveRepoPathFailures(t *testing.T) {
	t.Setenv(envProfilesDir, "")
	dir, err := CatalogDir()
	if err != nil {
		t.Fatalf("catalog dir default: %v", err)
	}
	if filepath.Base(dir) != "profiles" {
		t.Fatalf("unexpected default profiles dir %q", dir)
	}

	if _, err := ResolveRepoPath("does/not/exist"); err == nil {
		t.Fatal("expected missing repo path error")
	}
	if root, ok := walkToVersion(t.TempDir()); ok || root != "" {
		t.Fatalf("expected walkToVersion miss, got %q %v", root, ok)
	}
	if _, err := repoRoot(); err != nil {
		t.Fatalf("expected repoRoot from current repo to succeed: %v", err)
	}

	temp := t.TempDir()
	t.Chdir(temp)
	t.Setenv(envProfilesDir, "")
	if _, err := CatalogDir(); err == nil {
		t.Fatal("expected CatalogDir failure outside repo without override")
	}
	if _, err := repoRoot(); err == nil {
		t.Fatal("expected repoRoot failure outside repo")
	}
	override := filepath.Join(temp, "x", "y", "profiles")
	if err := os.MkdirAll(override, 0o700); err != nil {
		t.Fatalf("mkdir override: %v", err)
	}
	t.Setenv(envProfilesDir, override)
	fallbackTarget := filepath.Join(temp, "docs.txt")
	if err := os.WriteFile(fallbackTarget, []byte("x"), 0o600); err != nil {
		t.Fatalf("write fallback target: %v", err)
	}
	if got, err := ResolveRepoPath("docs.txt"); err != nil || got != fallbackTarget {
		t.Fatalf("ResolveRepoPath fallback = %q err=%v", got, err)
	}
	if findBenchmarkFunction("./internal/mcp", "BenchmarkToolsList") {
		t.Fatal("expected benchmark lookup to fail outside repo root")
	}
	if findEvalTest("TestMCPEndToEndEval") {
		t.Fatal("expected eval lookup to fail outside repo root")
	}
}

func TestCatalogDirRepoShapeFailures(t *testing.T) {
	t.Setenv(envProfilesDir, "")

	missingProfilesRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(missingProfilesRoot, "VERSION"), []byte("1"), 0o600); err != nil {
		t.Fatalf("write version file: %v", err)
	}
	t.Chdir(missingProfilesRoot)
	if _, err := CatalogDir(); err == nil {
		t.Fatal("expected missing profiles directory error")
	}

	notDirRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(notDirRoot, "VERSION"), []byte("1"), 0o600); err != nil {
		t.Fatalf("write version file: %v", err)
	}
	profilesPath := filepath.Join(notDirRoot, "apps", "server", "profiles")
	if err := os.MkdirAll(filepath.Dir(profilesPath), 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	if err := os.WriteFile(profilesPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write non-directory profiles path: %v", err)
	}
	t.Chdir(notDirRoot)
	if _, err := CatalogDir(); err == nil {
		t.Fatal("expected non-directory profiles path error")
	}
}

func TestRepoRootLookupEdgeCases(t *testing.T) {
	if _, err := repoRootWith(func() (string, error) {
		return "", os.ErrPermission
	}); err == nil {
		t.Fatal("expected injected getwd failure")
	}

	if findBenchmarkFunction("./internal/[", "BenchmarkAnything") {
		t.Fatal("expected malformed benchmark glob to fail")
	}

	benchmarkRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(benchmarkRoot, "VERSION"), []byte("1"), 0o600); err != nil {
		t.Fatalf("write version file: %v", err)
	}
	benchmarkPath := filepath.Join(benchmarkRoot, "apps", "server", "internal", "mcp", "broken_test.go")
	if err := os.MkdirAll(benchmarkPath, 0o755); err != nil {
		t.Fatalf("mkdir broken benchmark path: %v", err)
	}
	t.Chdir(benchmarkRoot)
	if findBenchmarkFunction("./internal/mcp", "BenchmarkAnything") {
		t.Fatal("expected benchmark lookup with unreadable match to fail")
	}

	globRootBase := t.TempDir()
	globRoot := filepath.Join(globRootBase, "repo[")
	if err := os.MkdirAll(filepath.Join(globRoot, "apps", "server", "internal", "evals"), 0o755); err != nil {
		t.Fatalf("mkdir glob root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(globRoot, "VERSION"), []byte("1"), 0o600); err != nil {
		t.Fatalf("write glob root version file: %v", err)
	}
	t.Chdir(globRoot)
	if findEvalTest("TestAnything") {
		t.Fatal("expected malformed eval glob to fail")
	}

	evalRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(evalRoot, "VERSION"), []byte("1"), 0o600); err != nil {
		t.Fatalf("write eval version file: %v", err)
	}
	evalPath := filepath.Join(evalRoot, "apps", "server", "internal", "evals", "broken_test.go")
	if err := os.MkdirAll(evalPath, 0o755); err != nil {
		t.Fatalf("mkdir broken eval path: %v", err)
	}
	t.Chdir(evalRoot)
	if findEvalTest("TestAnything") {
		t.Fatal("expected eval lookup with unreadable match to fail")
	}

	overrideRoot := t.TempDir()
	profilesDir := filepath.Join(overrideRoot, "apps", "server", "profiles")
	if err := os.MkdirAll(profilesDir, 0o755); err != nil {
		t.Fatalf("mkdir override profiles: %v", err)
	}
	if err := os.WriteFile(filepath.Join(overrideRoot, "VERSION"), []byte("1"), 0o600); err != nil {
		t.Fatalf("write override version: %v", err)
	}
	t.Chdir(t.TempDir())
	t.Setenv(envProfilesDir, profilesDir)
	if root, err := repoRoot(); err != nil || root != overrideRoot {
		t.Fatalf("expected repoRoot fallback from HASP_PROFILES_DIR, got %q err=%v", root, err)
	}
}
