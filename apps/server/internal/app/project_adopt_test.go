package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestProjectAdoptPreviewAndAdopt(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv(paths.EnvHome, homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	baseDir := t.TempDir()
	repoA := filepath.Join(baseDir, "repo-a")
	repoB := filepath.Join(baseDir, "repo-b")
	if err := os.MkdirAll(repoA, 0o755); err != nil {
		t.Fatalf("mkdir repoA: %v", err)
	}
	if err := os.MkdirAll(repoB, 0o755); err != nil {
		t.Fatalf("mkdir repoB: %v", err)
	}
	if out, err := run("git", "-C", repoA, "init"); err != nil {
		t.Fatalf("git init repoA: %v: %s", err, out)
	}
	if out, err := run("git", "-C", repoB, "init"); err != nil {
		t.Fatalf("git init repoB: %v: %s", err, out)
	}

	origLoad := loadCLIConfigAppFn
	t.Cleanup(func() { loadCLIConfigAppFn = origLoad })
	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		return paths.CLIConfig{
			AutoProtectRepos:     boolPtr(true),
			AutoInstallHooks:     boolPtr(false),
			DefaultCapturePolicy: string(store.PolicyAccess),
		}, nil
	}

	var previewOut bytes.Buffer
	if err := Run(context.Background(), []string{"project", "adopt", "--json", "--under", baseDir, "--preview"}, bytes.NewBuffer(nil), &previewOut, io.Discard); err != nil {
		t.Fatalf("project adopt preview: %v", err)
	}
	var preview projectAdoptResult
	if err := json.Unmarshal(previewOut.Bytes(), &preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if !preview.Preview || preview.ScannedRoots != 2 || len(preview.Candidates) != 2 {
		t.Fatalf("unexpected preview payload: %+v", preview)
	}
	for _, candidate := range preview.Candidates {
		if candidate.Reason != "would adopt" || candidate.Adopted || candidate.AlreadyManaged {
			t.Fatalf("unexpected preview candidate: %+v", candidate)
		}
		if candidate.HooksEnabled {
			t.Fatalf("expected hooks disabled by defaults in preview: %+v", candidate)
		}
		if candidate.DefaultPolicy != store.PolicyAccess {
			t.Fatalf("expected default policy access, got %+v", candidate)
		}
	}

	var adoptOut bytes.Buffer
	if err := Run(context.Background(), []string{"project", "adopt", "--json", "--under", baseDir}, bytes.NewBuffer(nil), &adoptOut, io.Discard); err != nil {
		t.Fatalf("project adopt: %v", err)
	}
	var adopted projectAdoptResult
	if err := json.Unmarshal(adoptOut.Bytes(), &adopted); err != nil {
		t.Fatalf("decode adopt: %v", err)
	}
	if adopted.AdoptedCount != 2 {
		t.Fatalf("expected 2 adopted repos, got %+v", adopted)
	}
	for _, candidate := range adopted.Candidates {
		if !candidate.Adopted || candidate.Reason != "adopted" {
			t.Fatalf("unexpected adopted candidate: %+v", candidate)
		}
	}

	var secondOut bytes.Buffer
	if err := Run(context.Background(), []string{"project", "adopt", "--json", "--under", baseDir, "--preview"}, bytes.NewBuffer(nil), &secondOut, io.Discard); err != nil {
		t.Fatalf("project adopt second preview: %v", err)
	}
	var second projectAdoptResult
	if err := json.Unmarshal(secondOut.Bytes(), &second); err != nil {
		t.Fatalf("decode second preview: %v", err)
	}
	for _, candidate := range second.Candidates {
		if !candidate.AlreadyManaged || candidate.Reason != "already managed" {
			t.Fatalf("expected already-managed candidate, got %+v", candidate)
		}
	}
}

func TestProjectAdoptSkipsNonProjectDirectories(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv(paths.EnvHome, homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	baseDir := t.TempDir()
	plain := filepath.Join(baseDir, "plain")
	repo := filepath.Join(baseDir, "repo")
	if err := os.MkdirAll(filepath.Join(plain, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir plain: %v", err)
	}
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if out, err := run("git", "-C", repo, "init"); err != nil {
		t.Fatalf("git init repo: %v: %s", err, out)
	}
	origLoad := loadCLIConfigAppFn
	t.Cleanup(func() { loadCLIConfigAppFn = origLoad })
	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		return paths.CLIConfig{AutoProtectRepos: boolPtr(true)}, nil
	}

	var out bytes.Buffer
	if err := Run(context.Background(), []string{"project", "adopt", "--json", "--under", baseDir, "--preview"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("project adopt preview: %v", err)
	}
	var payload projectAdoptResult
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if len(payload.Candidates) != 1 || !strings.Contains(payload.Candidates[0].ProjectRoot, "repo") {
		t.Fatalf("expected only git repo candidate, got %+v", payload)
	}
}

func TestDiscoverProjectRootsWalkFailure(t *testing.T) {
	lockAppSeams(t)
	origWalk := projectWalkDirFn
	defer func() { projectWalkDirFn = origWalk }()

	baseDir := t.TempDir()
	projectWalkDirFn = func(string, fs.WalkDirFunc) error { return errors.New("walk fail") }
	if _, err := discoverProjectRoots(context.Background(), baseDir); err == nil || !strings.Contains(err.Error(), "walk fail") {
		t.Fatalf("expected walk failure, got %v", err)
	}
}

func TestProjectAdoptCommandErrorBranches(t *testing.T) {
	lockAppSeams(t)

	origOpen := openVaultHandleFn
	origLoad := loadCLIConfigAppFn
	origWalk := projectWalkDirFn
	origCanon := projectCanonicalRootFn
	origInstallHooks := installHooksFn
	defer func() {
		openVaultHandleFn = origOpen
		loadCLIConfigAppFn = origLoad
		projectWalkDirFn = origWalk
		projectCanonicalRootFn = origCanon
		installHooksFn = origInstallHooks
	}()

	if err := projectAdoptCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected parse error")
	}

	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault fail") }
	if err := projectAdoptCommand(context.Background(), []string{}, io.Discard); err == nil || !strings.Contains(err.Error(), "vault fail") {
		t.Fatalf("expected vault failure, got %v", err)
	}

	homeDir := t.TempDir()
	t.Setenv(paths.EnvHome, homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	keyring := &memorySetupKeyring{}
	vaultStore, err := store.New(keyring)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil && !strings.Contains(err.Error(), "vault already exists") {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return handle, nil }

	loadCLIConfigAppFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, errors.New("load fail") }
	if err := projectAdoptCommand(context.Background(), []string{}, io.Discard); err == nil || !strings.Contains(err.Error(), "load fail") {
		t.Fatalf("expected defaults load failure, got %v", err)
	}

	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		autoProtect := true
		return paths.CLIConfig{AutoProtectRepos: &autoProtect}, nil
	}
	projectCanonicalRootFn = func(context.Context, string) (string, error) { return "", errors.New("canon fail") }
	if err := projectAdoptCommand(context.Background(), []string{}, io.Discard); err == nil || !strings.Contains(err.Error(), "canon fail") {
		t.Fatalf("expected canonical root failure, got %v", err)
	}

	baseDir := t.TempDir()
	projectCanonicalRootFn = origCanon
	projectWalkDirFn = func(string, fs.WalkDirFunc) error { return errors.New("walk fail") }
	if err := projectAdoptCommand(context.Background(), []string{"--under", baseDir}, io.Discard); err == nil || !strings.Contains(err.Error(), "walk fail") {
		t.Fatalf("expected discover failure, got %v", err)
	}

	projectWalkDirFn = func(root string, fn fs.WalkDirFunc) error {
		if err := fn(filepath.Join(root, "repo", ".git"), fakeDirEntry{name: ".git", dir: true}, nil); err != nil && !errors.Is(err, filepath.SkipDir) {
			return err
		}
		return nil
	}
	projectCanonicalRootFn = func(_ context.Context, path string) (string, error) {
		if filepath.Base(path) == ".git" {
			return filepath.Dir(path), nil
		}
		return path, nil
	}

	repoRoot := filepath.Join(baseDir, "repo")
	if _, err := handle.UpsertBinding(context.Background(), repoRoot, map[string]string{"secret_01": "missing_item"}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert bad binding: %v", err)
	}
	if err := projectAdoptCommand(context.Background(), []string{"--under", baseDir}, io.Discard); err == nil || !strings.Contains(err.Error(), "missing_item") || !strings.Contains(err.Error(), "hasp secret add --vault-only missing_item") {
		t.Fatalf("expected resolve binding failure, got %v", err)
	}

	if err := handle.DeleteBinding(context.Background(), repoRoot); err != nil {
		t.Fatalf("delete bad binding: %v", err)
	}
	if out, err := initTestGitRepo(repoRoot); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	installHooksFn = func(string) error { return errors.New("hook fail") }
	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		autoProtect := true
		autoInstallHooks := true
		return paths.CLIConfig{AutoProtectRepos: &autoProtect, AutoInstallHooks: &autoInstallHooks}, nil
	}
	if err := projectAdoptCommand(context.Background(), []string{"--under", baseDir}, io.Discard); err == nil || !strings.Contains(err.Error(), "hook fail") {
		t.Fatalf("expected bind project failure, got %v", err)
	}
}

func TestDiscoverProjectRootsAdditionalBranches(t *testing.T) {
	lockAppSeams(t)
	origWalk := projectWalkDirFn
	origCanon := projectCanonicalRootFn
	defer func() {
		projectWalkDirFn = origWalk
		projectCanonicalRootFn = origCanon
	}()

	baseDir := t.TempDir()
	projectCanonicalRootFn = func(context.Context, string) (string, error) {
		return baseDir, nil
	}
	projectWalkDirFn = func(root string, fn fs.WalkDirFunc) error {
		if err := fn(filepath.Join(root, ".git"), fakeDirEntry{name: ".git", dir: false}, nil); err != nil {
			return err
		}
		if err := fn(filepath.Join(root, "repo", ".git"), fakeDirEntry{name: ".git", dir: true}, errors.New("entry fail")); err == nil || !strings.Contains(err.Error(), "entry fail") {
			return errors.New("expected walkErr branch to return error")
		}
		if err := fn(filepath.Join(root, "repo", ".git"), fakeDirEntry{name: ".git", dir: true}, nil); err != nil && !errors.Is(err, filepath.SkipDir) {
			return err
		}
		return nil
	}

	projectCanonicalRootFn = func(_ context.Context, path string) (string, error) {
		if strings.Contains(path, filepath.Join(baseDir, "repo")) {
			return "", errors.New("candidate fail")
		}
		return baseDir, nil
	}
	if _, err := discoverProjectRoots(context.Background(), baseDir); err == nil || !strings.Contains(err.Error(), "candidate fail") {
		t.Fatalf("expected candidate canonicalization failure, got %v", err)
	}

	projectCanonicalRootFn = func(_ context.Context, path string) (string, error) { return filepath.Clean(path), nil }
	roots, err := discoverProjectRoots(context.Background(), baseDir)
	if err != nil {
		t.Fatalf("discover project roots success: %v", err)
	}
	if len(roots) != 2 {
		t.Fatalf("expected two discovered roots from file/dir .git entries, got %+v", roots)
	}
}

type fakeDirEntry struct {
	name string
	dir  bool
}

func (f fakeDirEntry) Name() string               { return f.name }
func (f fakeDirEntry) IsDir() bool                { return f.dir }
func (f fakeDirEntry) Type() fs.FileMode          { return 0 }
func (f fakeDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

func boolPtr(v bool) *bool { return &v }
