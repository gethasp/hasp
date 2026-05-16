package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestEnsureProjectBindingReusesExistingBindingWithoutAutoAdoptChecks(t *testing.T) {
	lockAppSeams(t)

	handle := newProjectContextAppHandle(t)
	projectRoot := t.TempDir()
	binding, err := handle.UpsertBinding(context.Background(), projectRoot, nil, store.PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	origLoad := loadCLIConfigAppFn
	origCanonical := appCanonicalProjectRootFn
	defer func() {
		loadCLIConfigAppFn = origLoad
		appCanonicalProjectRootFn = origCanonical
	}()
	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		return paths.CLIConfig{}, errors.New("defaults should not load for existing binding")
	}
	appCanonicalProjectRootFn = func(context.Context, string) (string, error) {
		return "", errors.New("canonicalization should not run for existing binding")
	}

	resolved, _, autoAdopted, err := ensureProjectBinding(context.Background(), handle, projectRoot)
	if err != nil {
		t.Fatalf("ensure project binding: %v", err)
	}
	if autoAdopted {
		t.Fatal("expected existing binding reuse without auto-adoption")
	}
	if resolved.ID != binding.ID {
		t.Fatalf("binding id=%q, want %q", resolved.ID, binding.ID)
	}
}

func TestBindProjectDoesNotPersistHookInstalledWhenHookInstallFails(t *testing.T) {
	lockAppSeams(t)

	handle := newProjectContextAppHandle(t)
	projectRoot := t.TempDir()

	origInstallHooks := installHooksFn
	defer func() { installHooksFn = origInstallHooks }()
	installHooksFn = func(string) error { return errors.New("hook fail") }

	if _, err := bindProject(context.Background(), handle, projectRoot, nil, store.PolicySession, true); err == nil || !strings.Contains(err.Error(), "hook fail") {
		t.Fatalf("expected hook install failure, got %v", err)
	}

	resolved, _, err := handle.ResolveBindingView(context.Background(), projectRoot)
	if err != nil {
		t.Fatalf("resolve binding: %v", err)
	}
	if resolved.ID != "" || resolved.HookInstalled {
		t.Fatalf("binding=%+v, want no binding persisted after failed install", resolved)
	}
}

func newProjectContextAppHandle(t *testing.T) *store.Handle {
	t.Helper()
	t.Setenv(paths.EnvHome, t.TempDir())

	vaultStore, err := store.New(&memorySetupKeyring{})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}
	return handle
}
