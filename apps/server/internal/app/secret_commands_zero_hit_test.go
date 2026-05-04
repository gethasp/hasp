package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/ttyutil"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestSecretCommandsZeroHitBranches(t *testing.T) {
	lockAppSeams(t)

	handle := newSecretHandleForTests(t)

	origOpen := openVaultHandleFn
	origGetwd := secretGetwdFn
	origCanon := appCanonicalProjectRootFn
	origResolveBinding := resolveBindingViewAppFn
	origUpsert := secretUpsertItemFn
	origGetItem := secretGetItemFn
	origDelete := secretDeleteItemFn
	origBind := secretBindItemAliasFn
	origHide := secretHideItemFn
	defer func() {
		openVaultHandleFn = origOpen
		secretGetwdFn = origGetwd
		appCanonicalProjectRootFn = origCanon
		resolveBindingViewAppFn = origResolveBinding
		secretUpsertItemFn = origUpsert
		secretGetItemFn = origGetItem
		secretDeleteItemFn = origDelete
		secretBindItemAliasFn = origBind
		secretHideItemFn = origHide
	}()

	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault fail") }
	if err := secretAddCommand(context.Background(), []string{"KEY=value"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected add open failure, got %v", err)
	}
	if err := secretUpdateCommand(context.Background(), []string{"KEY=value"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected update open failure, got %v", err)
	}
	if err := secretDeleteCommand(context.Background(), []string{"--yes", "KEY"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected delete open failure, got %v", err)
	}
	if err := secretGetCommand(context.Background(), []string{"KEY"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected get open failure, got %v", err)
	}
	if err := secretListCommand(context.Background(), nil, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected list open failure, got %v", err)
	}
	if err := secretExposeCommand(context.Background(), []string{"KEY"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected expose open failure, got %v", err)
	}
	if err := secretHideCommand(context.Background(), []string{"KEY"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected hide open failure, got %v", err)
	}

	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return handle, nil }
	if err := secretAddCommand(context.Background(), nil, errReader{err: errors.New("add input fail")}, io.Discard, io.Discard); err == nil || err.Error() != "add input fail" {
		t.Fatalf("expected add input failure, got %v", err)
	}
	secretGetwdFn = func() (string, error) { return "/tmp/repo", nil }
	appCanonicalProjectRootFn = func(context.Context, string) (string, error) { return "", errors.New("project fail") }
	if err := secretAddCommand(context.Background(), []string{"KEY"}, bytes.NewBufferString("value\n"), io.Discard, io.Discard); err == nil || err.Error() != "project fail" {
		t.Fatalf("expected add project context failure, got %v", err)
	}
	appCanonicalProjectRootFn = origCanon
	resolveBindingViewAppFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("binding fail")
	}
	gitRoot := t.TempDir()
	if out, err := run("git", "-C", gitRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if err := secretAddCommand(context.Background(), []string{"--project-root", gitRoot, "--expose=always", "KEY"}, bytes.NewBufferString("value\n"), io.Discard, io.Discard); err == nil || err.Error() != "binding fail" {
		t.Fatalf("expected add binding failure, got %v", err)
	}
	resolveBindingViewAppFn = origResolveBinding

	if _, err := handle.UpsertItem("TOKEN", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{}); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	if err := secretAddCommand(context.Background(), []string{"--expose=always", "TOKEN"}, bytes.NewBufferString("value\n4\n"), io.Discard, io.Discard); err == nil || err.Error() != "secret add cancelled" {
		t.Fatalf("expected add collision cancellation, got %v", err)
	}
	secretUpsertItemFn = func(*store.Handle, string, store.ItemKind, []byte, store.ItemMetadata) (store.Item, error) {
		return store.Item{}, errors.New("upsert fail")
	}
	if err := secretAddCommand(context.Background(), []string{"--expose=always", "OTHER"}, bytes.NewBufferString("value\n"), io.Discard, io.Discard); err == nil || err.Error() != "upsert fail" {
		t.Fatalf("expected add upsert failure, got %v", err)
	}
	secretUpsertItemFn = origUpsert
	secretBindItemAliasFn = func(*store.Handle, context.Context, string, string) (string, error) {
		return "", errors.New("bind fail")
	}
	if err := secretAddCommand(context.Background(), []string{"--project-root", gitRoot, "--expose=always", "YET_ANOTHER"}, bytes.NewBufferString("value\n"), io.Discard, io.Discard); err == nil || err.Error() != "bind fail" {
		t.Fatalf("expected add bind failure, got %v", err)
	}
	secretBindItemAliasFn = origBind

	if err := secretUpdateCommand(context.Background(), nil, errReader{err: errors.New("update input fail")}, io.Discard, io.Discard); err == nil || err.Error() != "update input fail" {
		t.Fatalf("expected update input failure, got %v", err)
	}
	secretGetItemFn = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("get fail") }
	if err := secretUpdateCommand(context.Background(), []string{"TOKEN"}, bytes.NewBufferString("value\n"), io.Discard, io.Discard); err == nil || err.Error() != "get fail" {
		t.Fatalf("expected update get failure, got %v", err)
	}
	secretGetItemFn = origGetItem

	if err := secretDeleteCommand(context.Background(), nil, errReader{err: errors.New("delete input fail")}, io.Discard, io.Discard); err == nil || err.Error() != "delete input fail" {
		t.Fatalf("expected delete input failure, got %v", err)
	}
	if err := secretDeleteCommand(context.Background(), []string{"TOKEN"}, errReader{err: errors.New("read fail")}, io.Discard, io.Discard); err == nil || err.Error() != "read fail" {
		t.Fatalf("expected delete confirm failure, got %v", err)
	}
	secretDeleteItemFn = func(*store.Handle, string) error { return errors.New("delete fail") }
	if err := secretDeleteCommand(context.Background(), []string{"--yes", "TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || err.Error() != "delete fail" {
		t.Fatalf("expected delete operation failure, got %v", err)
	}
	secretDeleteItemFn = origDelete

	if err := secretGetCommand(context.Background(), nil, errReader{err: errors.New("get input fail")}, io.Discard, io.Discard); err == nil || err.Error() != "get input fail" {
		t.Fatalf("expected get input failure, got %v", err)
	}
	secretGetItemFn = func(*store.Handle, string) (store.Item, error) {
		return store.Item{Name: "file_secret", Kind: store.ItemKindFile, Value: []byte("abc")}, nil
	}
	if err := secretGetCommand(context.Background(), []string{"--reveal", "file_secret"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("expected file reveal success, got %v", err)
	}
	secretGetItemFn = origGetItem
	if err := secretGetCommand(context.Background(), []string{"--reveal", "TOKEN"}, bytes.NewBuffer(nil), errWriter{err: errors.New("reveal write fail")}, io.Discard); err == nil || err.Error() != "reveal write fail" {
		t.Fatalf("expected reveal write failure, got %v", err)
	}
	// hasp-jx3r: newline is now only appended when TTY or --newline is set.
	// Use --newline to force the second write and verify the error propagates.
	if err := secretGetCommand(context.Background(), []string{"--reveal", "--newline", "TOKEN"}, bytes.NewBuffer(nil), &failSecondWriteWriter{}, io.Discard); err == nil {
		t.Fatal("expected newline failure after kv reveal with --newline")
	}

	if err := secretListCommand(context.Background(), nil, errWriter{err: errors.New("list encode fail")}); err == nil || err.Error() != "list encode fail" {
		t.Fatalf("expected list encode failure, got %v", err)
	}

	if err := secretExposeCommand(context.Background(), nil, errReader{err: errors.New("expose input fail")}, io.Discard, io.Discard); err == nil || err.Error() != "expose input fail" {
		t.Fatalf("expected expose input failure, got %v", err)
	}
	appCanonicalProjectRootFn = func(context.Context, string) (string, error) { return "", errors.New("expose project fail") }
	if err := secretExposeCommand(context.Background(), []string{"TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || err.Error() != "expose project fail" {
		t.Fatalf("expected expose project failure, got %v", err)
	}
	appCanonicalProjectRootFn = origCanon
	resolveBindingViewAppFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("expose binding fail")
	}
	if err := secretExposeCommand(context.Background(), []string{"--project-root", gitRoot, "TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || err.Error() != "expose binding fail" {
		t.Fatalf("expected expose binding failure, got %v", err)
	}
	resolveBindingViewAppFn = origResolveBinding
	secretBindItemAliasFn = func(*store.Handle, context.Context, string, string) (string, error) {
		return "", errors.New("expose bind fail")
	}
	if err := secretExposeCommand(context.Background(), []string{"--project-root", gitRoot, "TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || err.Error() != "expose bind fail" {
		t.Fatalf("expected expose bind failure, got %v", err)
	}
	secretBindItemAliasFn = origBind

	if err := secretHideCommand(context.Background(), nil, errReader{err: errors.New("hide input fail")}, io.Discard, io.Discard); err == nil || err.Error() != "hide input fail" {
		t.Fatalf("expected hide input failure, got %v", err)
	}
	appCanonicalProjectRootFn = func(context.Context, string) (string, error) { return "", errors.New("hide project fail") }
	if err := secretHideCommand(context.Background(), []string{"TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || err.Error() != "hide project fail" {
		t.Fatalf("expected hide project failure, got %v", err)
	}
	appCanonicalProjectRootFn = origCanon
	secretHideItemFn = func(*store.Handle, context.Context, string, string) ([]string, error) {
		return nil, errors.New("hide fail")
	}
	if err := secretHideCommand(context.Background(), []string{"--project-root", gitRoot, "TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || err.Error() != "hide fail" {
		t.Fatalf("expected hide operation failure, got %v", err)
	}
}

func TestSecretCommandHelpersZeroHitBranches(t *testing.T) {
	prompt := newSecretPrompt(errReader{err: errors.New("line fail")}, io.Discard, io.Discard)
	if _, err := secretAddInputs(nil, prompt); err == nil || err.Error() != "line fail" {
		t.Fatalf("expected add helper line failure, got %v", err)
	}
	prompt = newSecretPrompt(&partialErrReader{data: []byte("NAME\n"), err: errors.New("value fail")}, io.Discard, io.Discard)
	if _, err := secretAddInputs(nil, prompt); err == nil || err.Error() != "value fail" {
		t.Fatalf("expected add helper value failure, got %v", err)
	}
	prompt = newSecretPrompt(&partialErrReader{data: []byte("NAME\nvalue\n"), err: errors.New("confirm fail")}, io.Discard, io.Discard)
	if _, err := secretAddInputs(nil, prompt); err == nil || err.Error() != "confirm fail" {
		t.Fatalf("expected add helper confirm failure, got %v", err)
	}
	if inputs, err := secretUpdateInputs(nil, newSecretPrompt(&partialErrReader{data: []byte("NAME\n"), err: errors.New("update value fail")}, io.Discard, io.Discard)); err == nil || err.Error() != "update value fail" || inputs != nil {
		t.Fatalf("expected update helper value failure, got %+v err=%v", inputs, err)
	}
	if _, err := secretInputsFromArgs([]string{"PROMPT"}, newSecretPrompt(errReader{err: errors.New("prompted fail")}, io.Discard, io.Discard)); err == nil || err.Error() != "prompted fail" {
		t.Fatalf("expected inputs helper prompt failure, got %v", err)
	}
	if _, err := secretNameInputs([]string{"", "SECOND"}, newSecretPrompt(bytes.NewBuffer(nil), io.Discard, io.Discard), "Key name"); err == nil {
		t.Fatal("expected empty arg name failure")
	}
	if _, err := secretNameInputs(nil, newSecretPrompt(errReader{err: errors.New("name read fail")}, io.Discard, io.Discard), "Key name"); err == nil || err.Error() != "name read fail" {
		t.Fatalf("expected name helper read failure, got %v", err)
	}
	if names, err := secretNameInputs(nil, newSecretPrompt(bytes.NewBufferString("TOKEN\n"), io.Discard, io.Discard), "Key name"); err != nil || len(names) != 1 || names[0] != "TOKEN" {
		t.Fatalf("expected interactive name success, got %+v err=%v", names, err)
	}

	handle := newSecretHandleForTests(t)
	if _, err := handle.UpsertItem("TOKEN", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{}); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	if _, _, _, err := resolveSecretAddCollision(handle, "TOKEN", []byte("abc"), "", newSecretPrompt(errReader{err: errors.New("collision read fail")}, io.Discard, io.Discard)); err == nil || err.Error() != "collision read fail" {
		t.Fatalf("expected collision prompt failure, got %v", err)
	}
	if name, _, outcome, err := resolveSecretAddCollision(handle, "TOKEN", []byte("abc"), "", newSecretPrompt(bytes.NewBufferString("1\n"), io.Discard, io.Discard)); err != nil || name != "TOKEN" || outcome != "updated" {
		t.Fatalf("expected replace branch, got %q %q err=%v", name, outcome, err)
	}
	if name, _, outcome, err := resolveSecretAddCollision(handle, "TOKEN", []byte("abc"), "", newSecretPrompt(bytes.NewBufferString("3\n"), io.Discard, io.Discard)); err != nil || name != "TOKEN" || outcome != "skipped" {
		t.Fatalf("expected skip branch, got %q %q err=%v", name, outcome, err)
	}
	origGet := secretGetItemFn
	secretGetItemFn = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("lookup fail") }
	if _, _, _, err := resolveSecretAddCollision(handle, "TOKEN", []byte("abc"), "replace", newSecretPrompt(bytes.NewBuffer(nil), io.Discard, io.Discard)); err == nil || err.Error() != "lookup fail" {
		t.Fatalf("expected collision lookup failure, got %v", err)
	}
	secretGetItemFn = origGet

	if _, _, _, err := ensureProjectBindingExplicit(context.Background(), handle, "/not-a-repo"); err == nil {
		t.Fatal("expected explicit binding non-git failure")
	}
	origCanon := appCanonicalProjectRootFn
	appCanonicalProjectRootFn = func(context.Context, string) (string, error) { return "", errors.New("canon fail") }
	if _, _, _, err := ensureProjectBindingExplicit(context.Background(), handle, "/repo"); err == nil || err.Error() != "canon fail" {
		t.Fatalf("expected explicit binding canonical failure, got %v", err)
	}
	appCanonicalProjectRootFn = origCanon
	origInstallHooks := installHooksFn
	defer func() { installHooksFn = origInstallHooks }()
	gitRoot := t.TempDir()
	if out, err := run("git", "-C", gitRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	installHooksFn = func(string) error { return errors.New("install hook fail") }
	if _, _, _, err := ensureProjectBindingExplicit(context.Background(), handle, gitRoot); err == nil || err.Error() != "install hook fail" {
		t.Fatalf("expected explicit binding install hook failure, got %v", err)
	}
	installHooksFn = origInstallHooks

	if _, err := newSecretPrompt(bytes.NewBuffer(nil), io.Discard, errWriter{err: errors.New("masked prompt fail")}).secretValue("TOKEN"); err == nil || err.Error() != "masked prompt fail" {
		t.Fatalf("expected masked secret write failure, got %v", err)
	}
	if _, err := newSecretPrompt(errReader{err: errors.New("hidden fail")}, io.Discard, io.Discard).secretValue("TOKEN"); err == nil || err.Error() != "hidden fail" {
		t.Fatalf("expected masked secret hidden read failure, got %v", err)
	}
	if choice, renamed, err := newSecretPrompt(bytes.NewBufferString("2\n"), io.Discard, io.Discard).collision("TOKEN"); err != nil || choice != "rename" || renamed != "" {
		t.Fatalf("expected rename branch on EOF, got %q %q err=%v", choice, renamed, err)
	}
	if value, err := newSecretPrompt(errReader{err: errors.New("stdin fail")}, io.Discard, io.Discard).readHidden(); err == nil || value != nil {
		t.Fatalf("expected non-file hidden read failure, got %q err=%v", string(value), err)
	}
	tempFile, err := os.CreateTemp(t.TempDir(), "closed-secret-input")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	if err := tempFile.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	secretIsCharDeviceFn = func(*os.File) bool { return true }
	secretSetTTYEchoFn = func(*os.File, bool) error { return nil }
	if value, err := newSecretPrompt(tempFile, io.Discard, io.Discard).readHidden(); err == nil || value != nil {
		t.Fatalf("expected hidden read error on closed file, got %q err=%v", string(value), err)
	}
	tempFile2, err := os.CreateTemp(t.TempDir(), "closed-secret-input-2")
	if err != nil {
		t.Fatalf("temp file2: %v", err)
	}
	if err := tempFile2.Close(); err != nil {
		t.Fatalf("close temp file2: %v", err)
	}
	secretIsCharDeviceFn = func(*os.File) bool { return false }
	if value, err := newSecretPrompt(tempFile2, io.Discard, io.Discard).readHidden(); err == nil || value != nil {
		t.Fatalf("expected non-char closed file read error, got %q err=%v", string(value), err)
	}
	tempFile3, err := os.CreateTemp(t.TempDir(), "closed-secret-input-3")
	if err != nil {
		t.Fatalf("temp file3: %v", err)
	}
	if err := tempFile3.Close(); err != nil {
		t.Fatalf("close temp file3: %v", err)
	}
	secretIsCharDeviceFn = func(*os.File) bool { return true }
	secretSetTTYEchoFn = func(*os.File, bool) error { return errors.New("tty fail") }
	if value, err := newSecretPrompt(tempFile3, io.Discard, io.Discard).readHidden(); err == nil || value != nil {
		t.Fatalf("expected tty fallback read error, got %q err=%v", string(value), err)
	}
	if got, ok := ttyutil.StdinFile(nil); ok || got != nil {
		t.Fatalf("expected nil stdinFile result, got %v %v", got, ok)
	}
}

func newSecretHandleForTests(t *testing.T) *store.Handle {
	t.Helper()
	t.Setenv("HASP_HOME", t.TempDir())
	testStore := newTestStoreForSecretCommands(t)
	if err := testStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init secret test store: %v", err)
	}
	handle, err := testStore.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open secret test handle: %v", err)
	}
	return handle
}

func newTestStoreForSecretCommands(t *testing.T) *store.Store {
	t.Helper()
	keyring := &memorySetupKeyring{}
	testStore, err := store.New(keyring)
	if err != nil {
		t.Fatalf("new secret test store: %v", err)
	}
	return testStore
}

type partialErrReader struct {
	data []byte
	err  error
	read bool
}

func (r *partialErrReader) Read(p []byte) (int, error) {
	if !r.read {
		r.read = true
		n := copy(p, r.data)
		return n, nil
	}
	if r.err == nil {
		return 0, io.EOF
	}
	return 0, r.err
}

func TestSetupResidualBranches(t *testing.T) {
	lockAppSeams(t)

	origTimeout := setupConvenienceUnlockTimeout
	defer func() { setupConvenienceUnlockTimeout = origTimeout }()
	setupConvenienceUnlockTimeout = 0
	called := false
	if err := setupRunConvenienceUnlockStep(context.Background(), func(context.Context) error {
		called = true
		return nil
	}); err != nil || !called {
		t.Fatalf("expected zero-timeout convenience step to call directly, err=%v called=%v", err, called)
	}

	if err := setupWriteConfirmation(errWriter{err: errors.New("config exists fail")}, setupPlanPreview{ConfigExists: true}); err == nil || err.Error() != "config exists fail" {
		t.Fatalf("expected config exists write failure, got %v", err)
	}
}

type failSecondWriteWriter struct {
	writes int
}

func (w *failSecondWriteWriter) Write(data []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		return len(data), nil
	}
	return 0, errors.New("newline fail")
}
