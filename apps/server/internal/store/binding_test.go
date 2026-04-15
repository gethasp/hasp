package store

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBindingAliasGenerationAndSafeDiscovery(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, err := handle.UpsertItem("prod_api_token", ItemKindKV, []byte("value"), ItemMetadata{
		HumanLabel: "prod_api_token",
		Policy:     PolicySession,
		Tags:       []string{"production"},
	}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}

	projectRoot := t.TempDir()
	alias, err := handle.BindItemAlias(context.Background(), projectRoot, "prod_api_token")
	if err != nil {
		t.Fatalf("bind alias: %v", err)
	}
	if alias != "secret_01" {
		t.Fatalf("alias = %q, want secret_01", alias)
	}

	_, visible, err := handle.ResolveBindingView(context.Background(), projectRoot)
	if err != nil {
		t.Fatalf("resolve binding view: %v", err)
	}
	if len(visible) != 1 {
		t.Fatalf("visible refs = %d, want 1", len(visible))
	}
	if visible[0].Alias != "secret_01" || visible[0].PolicyLevel != PolicySession {
		t.Fatalf("unexpected visible ref: %+v", visible[0])
	}
}

func TestRepoManifestConflictBlocksResolution(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, err := handle.UpsertItem("staging_token", ItemKindKV, []byte("staging"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertItem("prod_token", ItemKindKV, []byte("prod"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}

	projectRoot := t.TempDir()
	manifest := `{"version":"v1","references":[{"alias":"secret_01","item":"staging_token"}]}`
	if err := os.WriteFile(filepath.Join(projectRoot, manifestFilename), []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "prod_token"}, PolicySession, true); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	if _, _, err := handle.ResolveBindingView(context.Background(), projectRoot); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("expected binding conflict, got %v", err)
	}
}

func TestCanonicalProjectRootUsesGitTopLevel(t *testing.T) {
	projectRoot := t.TempDir()
	subdir := filepath.Join(projectRoot, "nested", "dir")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("make nested dir: %v", err)
	}
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	resolved, err := CanonicalProjectRoot(context.Background(), subdir)
	if err != nil {
		t.Fatalf("canonical project root: %v", err)
	}
	want, err := filepath.EvalSymlinks(projectRoot)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	if resolved != want {
		t.Fatalf("resolved root = %q, want %q", resolved, want)
	}
}

func TestDeleteBindingRemovesAliases(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	projectRoot := t.TempDir()
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("abc123"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token"}, PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if err := handle.DeleteBinding(context.Background(), projectRoot); err != nil {
		t.Fatalf("delete binding: %v", err)
	}
	binding, visible, err := handle.ResolveBindingView(context.Background(), projectRoot)
	if err != nil {
		t.Fatalf("resolve binding view: %v", err)
	}
	if binding.ID != "" || len(visible) != 0 {
		t.Fatalf("expected empty binding after delete, got %+v visible=%v", binding, visible)
	}
}

func TestLoadRepoManifestAndHelperUtilities(t *testing.T) {
	projectRoot := t.TempDir()
	if _, err := LoadRepoManifest(projectRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected missing manifest error, got %v", err)
	}

	manifestPath := filepath.Join(projectRoot, manifestFilename)
	if err := os.WriteFile(manifestPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write malformed manifest: %v", err)
	}
	if _, err := LoadRepoManifest(projectRoot); err == nil {
		t.Fatal("expected malformed manifest error")
	}

	if got := GenerateNeutralAlias(ItemKindFile, map[string]string{"file_01": "cert"}); got != "file_02" {
		t.Fatalf("expected file_02, got %q", got)
	}
	if got := GenerateNeutralAlias(ItemKind("custom"), map[string]string{}); got != "credential_01" {
		t.Fatalf("expected credential_01, got %q", got)
	}
	if normalizePolicy(SecretPolicy("bogus")) != PolicyAuto {
		t.Fatal("expected bogus policy to normalize to auto")
	}

	visible := []VisibleReference{{Alias: "secret_02"}, {Alias: "secret_01"}}
	sortVisibleReferences(visible)
	if visible[0].Alias != "secret_01" {
		t.Fatalf("expected sorted visible references, got %+v", visible)
	}
}

func TestBindingOperationsHandlePersistFailureAndNilAudit(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	projectRoot := t.TempDir()
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("abc123"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertItem("db_url", ItemKindKV, []byte("postgres://localhost"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}

	handle.store.audit = nil
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token"}, PolicySession, false); err != nil {
		t.Fatalf("upsert binding without audit: %v", err)
	}
	if _, err := handle.BindItemAlias(context.Background(), projectRoot, "api_token"); err != nil {
		t.Fatalf("bind alias without audit: %v", err)
	}

	if err := os.WriteFile(store.paths.StatePath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write malformed envelope: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_02": "api_token"}, PolicySession, false); err == nil {
		t.Fatal("expected upsert binding persist failure")
	}
	if _, err := handle.BindItemAlias(context.Background(), projectRoot, "db_url"); err == nil {
		t.Fatal("expected bind alias persist failure")
	}
	if err := handle.DeleteBinding(context.Background(), projectRoot); err == nil {
		t.Fatal("expected delete binding persist failure")
	}
}

func run(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}
