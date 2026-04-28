package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestImportSupportHelpers(t *testing.T) {
	if _, err := prepareImport("", "auto", "", nil, false, nil); err == nil {
		t.Fatal("expected missing import path error")
	}
	if _, err := prepareImport("-", "env", "", nil, false, nil); err == nil {
		t.Fatal("expected missing stdin reader error")
	}

	stdinPrepared, err := prepareImport("-", "env", "", bytes.NewBufferString("export API_TOKEN='abc123'\n"), true, map[string]string{})
	if err != nil {
		t.Fatalf("prepare stdin import: %v", err)
	}
	defer stdinPrepared.Cleanup()
	if stdinPrepared.Preview.Source != "stdin" || !stdinPrepared.Preview.LocalHygienePath || len(stdinPrepared.ProjectedNames) != 1 {
		t.Fatalf("unexpected stdin preview: %+v", stdinPrepared)
	}

	jsonPrepared, err := prepareImport("stdin.json", "json", "", bytes.NewBufferString("{}"), true, map[string]string{})
	if err == nil {
		jsonPrepared.Cleanup()
	}
	jsonItems, err := previewImportItems("stdin.json", "json", "", []byte("{}"), true, map[string]string{})
	if err != nil {
		t.Fatalf("preview import items json: %v", err)
	}
	if len(jsonItems) != 1 || jsonItems[0].Kind != store.ItemKindFile || jsonItems[0].Alias == "" {
		t.Fatalf("unexpected preview json import items: %+v", jsonItems)
	}

	filePath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(filePath, []byte("API_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	if _, source, format, actualPath, cleanup, err := importBytes(filePath, "auto", nil); err != nil {
		t.Fatalf("import bytes file: %v", err)
	} else if source != filePath || format != "env" || actualPath != filePath || cleanup != nil {
		t.Fatalf("unexpected file import bytes result")
	}
	if _, _, _, _, _, err := importBytes(filepath.Join(t.TempDir(), "missing.env"), "auto", nil); err == nil {
		t.Fatal("expected missing file import error")
	}
	if _, _, _, _, _, err := importBytes("-", "env", errReader{err: errors.New("read fail")}); err == nil || !strings.Contains(err.Error(), "read fail") {
		t.Fatalf("expected stdin read failure, got %v", err)
	}
	if _, _, _, _, _, err := importBytes("-", "bogus", bytes.NewBufferString("x")); err == nil {
		t.Fatal("expected unsupported format error")
	}
	if _, _, _, _, _, err := importBytes("-", "bogus", bytes.NewBufferString("API_TOKEN=abc123\n")); err == nil {
		t.Fatal("expected stdin format resolution failure")
	}
	closeDeps := defaultImportSupportDeps()
	closeDeps.CreateTemp = func(dir, pattern string) (*os.File, error) {
		file, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		return file, nil
	}
	if _, _, _, _, _, err := importBytesWithDeps("-", "env", bytes.NewBufferString("API_TOKEN=abc123\n"), closeDeps); err == nil {
		t.Fatalf("expected temp close failure, got %v", err)
	}
	if _, err := resolveImportFormat("secret.txt", "auto"); err == nil {
		t.Fatal("expected unsupported auto format")
	}
	if format, err := resolveImportFormat("secret.json", "auto"); err != nil || format != "json" {
		t.Fatalf("expected json auto format, got %q err=%v", format, err)
	}
	if _, err := previewImportItems("source", "bogus", "", []byte("x"), false, nil); err == nil {
		t.Fatal("expected unsupported preview format")
	}
	if _, err := previewEnvImportItems([]byte("BROKEN"), false, nil); err == nil {
		t.Fatal("expected invalid env preview line")
	}
	if items, err := previewEnvImportReader(bytes.NewBufferString("# comment\nVALUE=\"quoted\"\n"), false, nil); err != nil || len(items) != 1 || items[0].Name != "VALUE" {
		t.Fatalf("expected quoted preview env item, got %+v err=%v", items, err)
	}
	jsonItems, err = previewJSONImportItem("stdin", "", true, map[string]string{})
	if err != nil {
		t.Fatalf("preview json import item: %v", err)
	}
	if len(jsonItems) != 1 || jsonItems[0].Kind != store.ItemKindFile || jsonItems[0].Alias == "" {
		t.Fatalf("unexpected json preview items: %+v", jsonItems)
	}
	if alias := projectAlias(store.ItemKindKV, "api_token", map[string]string{"secret_01": "api_token"}); alias != "secret_01" {
		t.Fatalf("expected existing alias reuse, got %q", alias)
	}
	if _, err := previewEnvImportReader(errReader{err: errors.New("scan fail")}, false, nil); err == nil || !strings.Contains(err.Error(), "scan fail") {
		t.Fatalf("expected preview scanner failure, got %v", err)
	}

	createFailDeps := defaultImportSupportDeps()
	createFailDeps.CreateTemp = func(string, string) (*os.File, error) { return nil, errors.New("create fail") }
	if _, _, _, _, _, err := importBytesWithDeps("-", "env", bytes.NewBufferString("API_TOKEN=abc123\n"), createFailDeps); err == nil || !strings.Contains(err.Error(), "create fail") {
		t.Fatalf("expected create temp failure, got %v", err)
	}
	writeFailDeps := defaultImportSupportDeps()
	writeFailDeps.WriteFile = func(string, []byte, os.FileMode) error { return errors.New("write fail") }
	if _, _, _, _, _, err := importBytesWithDeps("-", "env", bytes.NewBufferString("API_TOKEN=abc123\n"), writeFailDeps); err == nil || !strings.Contains(err.Error(), "write fail") {
		t.Fatalf("expected write import failure, got %v", err)
	}
	if _, err := prepareImport("-", "env", "", bytes.NewBufferString("BROKEN"), false, nil); err == nil {
		t.Fatal("expected prepareImport preview failure for invalid env stdin")
	}

	var out bytes.Buffer
	if err := encodeImportCommandResultWithMode(context.Background(), &out, stdinPrepared.Preview, &store.ImportResult{Imported: []store.ImportedItem{{Name: "API_TOKEN", Kind: store.ItemKindKV}}}, true, true); err != nil {
		t.Fatalf("encode import result: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode import command result: %v", err)
	}
	if payload["applied"] != true {
		t.Fatalf("expected applied=true, got %v", payload)
	}
	if names := projectedNames([]importPlanItem{{Name: "a"}, {Name: "b"}}); len(names) != 2 || names[0] != "a" || names[1] != "b" {
		t.Fatalf("unexpected projected names: %v", names)
	}
}

func TestImportCommandCompatibilityBranches(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := importCommandWithInput(context.Background(), []string{"--format", "bogus", "-"}, bytes.NewBufferString("x"), io.Discard); err == nil {
		t.Fatal("expected unsupported format in import command")
	}
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "secret_01=api_token"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("project bind: %v", err)
	}
	if err := importCommandWithInput(context.Background(), []string{"--bind", "--project-root", projectRoot, "--preview", "--format", "env", "-"}, bytes.NewBufferString("DATABASE_URL=postgres://localhost\n"), io.Discard); err != nil {
		t.Fatalf("expected preview import with bootstrap alias context to succeed: %v", err)
	}

	origNewStore := newVaultStoreFn
	defer func() { newVaultStoreFn = origNewStore }()
	newVaultStoreFn = func() (*store.Store, error) { return nil, errors.New("store fail") }
	if err := importCommandWithInput(context.Background(), []string{"--format", "env", "-"}, bytes.NewBufferString("API_TOKEN=abc123\n"), io.Discard); err == nil || err.Error() != "store fail" {
		t.Fatalf("expected store failure, got %v", err)
	}
	newVaultStoreFn = origNewStore
	badJSONPath := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badJSONPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write bad json: %v", err)
	}
	if err := importCommandWithInput(context.Background(), []string{badJSONPath}, bytes.NewBuffer(nil), io.Discard); err == nil {
		t.Fatal("expected import command json decode failure")
	}
}

func TestApplyBootstrapImportsResidualBranches(t *testing.T) {
	lockAppSeams(t)

	deps := defaultBootstrapDeps()

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	vaultStore, err := newVaultStoreFn()
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	handle, err := openStoreWithPasswordFn(context.Background(), vaultStore, "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	binding, _, err := deps.ResolveBindingView(handle, context.Background(), projectRoot)
	if err != nil {
		t.Fatalf("initial binding view: %v", err)
	}

	badJSONPath := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badJSONPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write bad json: %v", err)
	}
	if _, _, _, _, err := applyBootstrapImports(context.Background(), handle, bootstrapOptions{ProjectRoot: projectRoot, ImportPaths: []string{badJSONPath}}, binding, bytes.NewBuffer(nil), deps); err == nil {
		t.Fatal("expected applyBootstrapImports import-path failure")
	}

	goodEnvPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(goodEnvPath, []byte("API_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	failingDeps := deps
	failingDeps.ResolveBindingView = failingResolveBinding("post-import binding fail")
	if _, _, _, _, err := applyBootstrapImports(context.Background(), handle, bootstrapOptions{ProjectRoot: projectRoot, ImportPaths: []string{goodEnvPath}}, binding, bytes.NewBuffer(nil), failingDeps); err == nil || !strings.Contains(err.Error(), "post-import binding fail") {
		t.Fatalf("expected applyBootstrapImports post-import resolve failure, got %v", err)
	}
}
