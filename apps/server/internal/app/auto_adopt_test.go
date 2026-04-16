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

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestLoadProjectDefaults(t *testing.T) {
	lockAppSeams(t)

	origLoad := loadCLIConfigAppFn
	defer func() { loadCLIConfigAppFn = origLoad }()

	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		return paths.CLIConfig{}, nil
	}
	defaults, err := loadProjectDefaults()
	if err != nil {
		t.Fatalf("load project defaults: %v", err)
	}
	if !defaults.AutoProtectRepos || !defaults.AutoInstallHooks || defaults.DefaultPolicy != store.PolicySession {
		t.Fatalf("unexpected defaults %+v", defaults)
	}

	autoProtect := false
	autoInstallHooks := false
	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		return paths.CLIConfig{
			AutoProtectRepos:     &autoProtect,
			AutoInstallHooks:     &autoInstallHooks,
			DefaultCapturePolicy: string(store.PolicyAccess),
		}, nil
	}
	defaults, err = loadProjectDefaults()
	if err != nil {
		t.Fatalf("load explicit project defaults: %v", err)
	}
	if defaults.AutoProtectRepos || defaults.AutoInstallHooks || defaults.DefaultPolicy != store.PolicyAccess {
		t.Fatalf("unexpected explicit defaults %+v", defaults)
	}

	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		return paths.CLIConfig{}, errors.New("load fail")
	}
	if _, err := loadProjectDefaults(); err == nil || !strings.Contains(err.Error(), "load fail") {
		t.Fatalf("expected config load failure, got %v", err)
	}
}

func TestEnsureProjectBindingAutoAdopts(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv(paths.EnvHome, homeDir)

	keyring := &memorySetupKeyring{}
	vaultStore, err := store.New(keyring)
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

	origLoad := loadCLIConfigAppFn
	origInstallHooks := installHooksFn
	defer func() {
		loadCLIConfigAppFn = origLoad
		installHooksFn = origInstallHooks
	}()

	projectRoot := t.TempDir()
	hooksCalled := 0
	installHooksFn = func(string) error {
		hooksCalled++
		return nil
	}
	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		autoProtect := true
		autoInstallHooks := true
		return paths.CLIConfig{
			AutoProtectRepos:     &autoProtect,
			AutoInstallHooks:     &autoInstallHooks,
			DefaultCapturePolicy: string(store.PolicyAccess),
		}, nil
	}

	binding, visible, autoAdopted, err := ensureProjectBinding(context.Background(), handle, projectRoot)
	if err != nil {
		t.Fatalf("ensure project binding: %v", err)
	}
	if !autoAdopted || binding.ID == "" || binding.DefaultCapturePolicy != store.PolicyAccess {
		t.Fatalf("unexpected adopted binding %+v auto=%v", binding, autoAdopted)
	}
	if hooksCalled != 0 {
		t.Fatalf("expected no hooks on non-git path, got %d", hooksCalled)
	}
	if len(visible) != 0 {
		t.Fatalf("expected no visible aliases on empty auto-adopt binding, got %+v", visible)
	}

	again, _, autoAdopted, err := ensureProjectBinding(context.Background(), handle, projectRoot)
	if err != nil {
		t.Fatalf("ensure project binding second pass: %v", err)
	}
	if autoAdopted || again.ID != binding.ID {
		t.Fatalf("expected second ensure to reuse binding, got %+v auto=%v", again, autoAdopted)
	}
}

func TestEnsureProjectBindingResidualFailures(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv(paths.EnvHome, homeDir)

	keyring := &memorySetupKeyring{}
	vaultStore, err := store.New(keyring)
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

	origLoad := loadCLIConfigAppFn
	origCanon := appCanonicalProjectRootFn
	origInstallHooks := installHooksFn
	origStat := projectPathStatFn
	defer func() {
		loadCLIConfigAppFn = origLoad
		appCanonicalProjectRootFn = origCanon
		installHooksFn = origInstallHooks
		projectPathStatFn = origStat
	}()

	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		autoProtect := true
		autoInstallHooks := true
		return paths.CLIConfig{
			AutoProtectRepos: &autoProtect,
			AutoInstallHooks: &autoInstallHooks,
		}, nil
	}
	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		return paths.CLIConfig{}, errors.New("load fail")
	}
	if _, _, _, err := ensureProjectBinding(context.Background(), handle, t.TempDir()); err == nil || !strings.Contains(err.Error(), "load fail") {
		t.Fatalf("expected defaults load failure, got %v", err)
	}
	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		autoProtect := true
		autoInstallHooks := true
		return paths.CLIConfig{
			AutoProtectRepos: &autoProtect,
			AutoInstallHooks: &autoInstallHooks,
		}, nil
	}
	appCanonicalProjectRootFn = func(context.Context, string) (string, error) {
		return "", errors.New("canon fail")
	}
	if _, _, _, err := ensureProjectBinding(context.Background(), handle, t.TempDir()); err == nil || !strings.Contains(err.Error(), "canon fail") {
		t.Fatalf("expected canonical root failure, got %v", err)
	}

	appCanonicalProjectRootFn = origCanon
	gitRoot := t.TempDir()
	if out, err := run("git", "-C", gitRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	installHooksFn = func(string) error { return errors.New("hook fail") }
	if _, _, _, err := ensureProjectBinding(context.Background(), handle, gitRoot); err == nil || !strings.Contains(err.Error(), "hook fail") {
		t.Fatalf("expected bind/install hooks failure, got %v", err)
	}

	if pathLooksLikeGitRepo("") {
		t.Fatal("expected blank root not to look like git repo")
	}
	projectPathStatFn = func(string) (os.FileInfo, error) { return nil, errors.New("stat fail") }
	if pathLooksLikeGitRepo(gitRoot) {
		t.Fatal("expected stat failure to report non-git repo")
	}
}

func TestEnsureProjectBindingAutoAdoptsGitRepoAndCommandsUseIt(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	origLoad := loadCLIConfigAppFn
	defer func() { loadCLIConfigAppFn = origLoad }()
	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		autoProtect := true
		autoInstallHooks := true
		return paths.CLIConfig{
			AutoProtectRepos:     &autoProtect,
			AutoInstallHooks:     &autoInstallHooks,
			DefaultCapturePolicy: string(store.PolicySession),
		}, nil
	}

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set: %v", err)
	}

	starter := newDaemonTestStarter(t)
	var runOut bytes.Buffer
	if err := runWithStarter(
		context.Background(),
		[]string{"run", "--project-root", projectRoot, "--env", "API_TOKEN=api_token", "--grant-project", "window", "--grant-secret", "session", "--", "sh", "-c", "printf '%s' \"$API_TOKEN\""},
		bytes.NewBuffer(nil),
		&runOut,
		io.Discard,
		starter,
	); err != nil {
		t.Fatalf("run with auto-adopted binding: %v", err)
	}
	if runOut.String() != "[REDACTED]" {
		t.Fatalf("unexpected redacted run output %q", runOut.String())
	}

	var statusOut bytes.Buffer
	if err := Run(context.Background(), []string{"project", "status", "--project-root", projectRoot}, bytes.NewBuffer(nil), &statusOut, &statusOut); err != nil {
		t.Fatalf("project status: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(statusOut.Bytes(), &payload); err != nil {
		t.Fatalf("decode project status: %v", err)
	}
	binding, ok := payload["binding"].(map[string]any)
	if !ok || strings.TrimSpace(binding["id"].(string)) == "" {
		t.Fatalf("expected auto-adopted binding id, got %+v", payload)
	}

	hookPath := filepath.Join(projectRoot, ".git", "hooks", "pre-commit")
	if _, err := os.Stat(hookPath); err != nil {
		t.Fatalf("expected auto-installed hook: %v", err)
	}
}

func TestEnsureProjectBindingRespectsDisabledAutoProtect(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv(paths.EnvHome, homeDir)

	keyring := &memorySetupKeyring{}
	vaultStore, err := store.New(keyring)
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

	origLoad := loadCLIConfigAppFn
	defer func() { loadCLIConfigAppFn = origLoad }()
	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		autoProtect := false
		return paths.CLIConfig{AutoProtectRepos: &autoProtect}, nil
	}

	binding, _, autoAdopted, err := ensureProjectBinding(context.Background(), handle, t.TempDir())
	if err != nil {
		t.Fatalf("ensure project binding: %v", err)
	}
	if autoAdopted || binding.ID != "" {
		t.Fatalf("expected no auto-adoption when disabled, got %+v auto=%v", binding, autoAdopted)
	}
	if err := requireProjectBinding(binding, "/tmp/workspace"); err == nil {
		t.Fatal("expected missing binding requirement error")
	}
	if autoAdoptEligible("/tmp/workspace", binding) != true {
		t.Fatal("expected empty binding workspace to be auto-adopt eligible")
	}
}
