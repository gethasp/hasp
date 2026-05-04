package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestImportEnvFileAndResolveAlias(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}

	projectRoot := t.TempDir()
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("API_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	result, err := handle.ImportPath(context.Background(), envPath, ImportOptions{
		ProjectRoot:   projectRoot,
		BindToProject: true,
	})
	if err != nil {
		t.Fatalf("import env file: %v", err)
	}
	if len(result.Imported) != 1 || result.Imported[0].Alias != "secret_01" {
		t.Fatalf("unexpected import result: %+v", result)
	}

	item, err := handle.ResolveReferenceItem(context.Background(), projectRoot, "secret_01")
	if err != nil {
		t.Fatalf("resolve alias: %v", err)
	}
	if string(item.Value) != "abc123" {
		t.Fatalf("resolved value = %q", string(item.Value))
	}
}

func TestImportJSONFileCreatesFileItem(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}

	jsonPath := filepath.Join(t.TempDir(), "service-account.json")
	if err := os.WriteFile(jsonPath, []byte(`{"client_email":"ops@gethasp.com"}`), 0o600); err != nil {
		t.Fatalf("write json file: %v", err)
	}

	result, err := handle.ImportPath(context.Background(), jsonPath, ImportOptions{})
	if err != nil {
		t.Fatalf("import json file: %v", err)
	}
	if len(result.Imported) != 1 || result.Imported[0].Kind != ItemKindFile {
		t.Fatalf("unexpected import result: %+v", result)
	}
}

func TestImportJSONFileBindsAliasWhenRequested(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	projectRoot := t.TempDir()
	jsonPath := filepath.Join(t.TempDir(), "service-account.json")
	if err := os.WriteFile(jsonPath, []byte(`{"client_email":"ops@gethasp.com"}`), 0o600); err != nil {
		t.Fatalf("write json file: %v", err)
	}
	result, err := handle.ImportPath(context.Background(), jsonPath, ImportOptions{ProjectRoot: projectRoot, BindToProject: true})
	if err != nil {
		t.Fatalf("import json file: %v", err)
	}
	if len(result.Imported) != 1 || result.Imported[0].Alias == "" {
		t.Fatalf("expected bound alias in import result, got %+v", result)
	}
}

func TestImportPathRejectsUnsupportedFormat(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	path := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(path, []byte("token"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := handle.ImportPath(context.Background(), path, ImportOptions{}); err == nil {
		t.Fatal("expected unsupported format error")
	}
}

func TestImportJSONCredentialUsesExplicitName(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	jsonPath := filepath.Join(t.TempDir(), "service-account.json")
	if err := os.WriteFile(jsonPath, []byte(`{"client_email":"ops@gethasp.com"}`), 0o600); err != nil {
		t.Fatalf("write json file: %v", err)
	}
	item, err := handle.ImportJSONCredential(jsonPath, "custom-name")
	if err != nil {
		t.Fatalf("import json credential: %v", err)
	}
	if item.Name != "custom-name" {
		t.Fatalf("item name = %q", item.Name)
	}
}

func TestResolveReferenceFailsClearly(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	projectRoot := t.TempDir()

	if _, err := handle.ResolveReference(context.Background(), projectRoot, "missing_alias"); !errors.Is(err, ErrReferenceNotFound) {
		t.Fatalf("expected missing reference error, got %v", err)
	}
}
