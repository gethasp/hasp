package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestCommandSeamErrorBranches(t *testing.T) {
	lockAppSeams(t)
	origNewStore := newVaultStoreFn
	origOpenStore := openStoreWithPasswordFn
	origEnsureSession := ensureSessionAppFn
	origOpenVaultHandle := openVaultHandleFn
	origAuthorizeReference := authorizeReferenceAppFn
	origAuthorizeItem := authorizeItemAppFn
	origRunnerExecute := runnerExecuteFn
	origCanonical := appCanonicalProjectRootFn
	origInstallHooks := installHooksFn
	origResolveBindingExec := resolveBindingViewExecFn
	origResolveBindingApp := resolveBindingViewAppFn
	origLoadCLI := loadCLIConfigAppFn
	origResolveReferenceExec := resolveReferenceExecFn
	origGetItemExec := getItemExecFn
	origResolveBindingSecrets := resolveBindingViewFn
	origGetItemSecrets := getItemAppFn
	origAuthorizeCapture := authorizeCaptureFn
	origGrantProject := grantProjectLeaseAppFn
	origGrantConvenience := grantConvenienceAppFn
	origOpenWriteEnv := openWriteEnvFileFn
	origWalkDir := walkProjectDirFn
	origAbs := absPathExecFn
	defer func() {
		newVaultStoreFn = origNewStore
		openStoreWithPasswordFn = origOpenStore
		ensureSessionAppFn = origEnsureSession
		openVaultHandleFn = origOpenVaultHandle
		authorizeReferenceAppFn = origAuthorizeReference
		authorizeItemAppFn = origAuthorizeItem
		runnerExecuteFn = origRunnerExecute
		appCanonicalProjectRootFn = origCanonical
		installHooksFn = origInstallHooks
		resolveBindingViewExecFn = origResolveBindingExec
		resolveBindingViewAppFn = origResolveBindingApp
		loadCLIConfigAppFn = origLoadCLI
		resolveReferenceExecFn = origResolveReferenceExec
		getItemExecFn = origGetItemExec
		resolveBindingViewFn = origResolveBindingSecrets
		getItemAppFn = origGetItemSecrets
		authorizeCaptureFn = origAuthorizeCapture
		grantProjectLeaseAppFn = origGrantProject
		grantConvenienceAppFn = origGrantConvenience
		openWriteEnvFileFn = origOpenWriteEnv
		walkProjectDirFn = origWalkDir
		absPathExecFn = origAbs
	}()

	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	newVaultStoreFn = func() (*store.Store, error) { return store.New(nil) }
	openStoreWithPasswordFn = func(context.Context, *store.Store, string) (*store.Handle, error) {
		return nil, errors.New("open fail")
	}
	if err := importCommandWithInput(context.Background(), []string{"-"}, bytes.NewBufferString("API_TOKEN=abc123\n"), io.Discard); err == nil || !strings.Contains(err.Error(), "open fail") {
		t.Fatalf("expected import open failure, got %v", err)
	}
	if err := setCommand(context.Background(), []string{"--name", "item", "--value", "v"}, io.Discard); err == nil || !strings.Contains(err.Error(), "open fail") {
		t.Fatalf("expected set open failure, got %v", err)
	}
	if err := redactCommand(context.Background(), bytes.NewBufferString("secret"), io.Discard); err == nil || !strings.Contains(err.Error(), "open fail") {
		t.Fatalf("expected redact open failure, got %v", err)
	}
	if err := projectBindCommand(context.Background(), []string{"--project-root", "."}, io.Discard); err == nil || !strings.Contains(err.Error(), "open fail") {
		t.Fatalf("expected project bind open failure, got %v", err)
	}
	if err := projectStatusCommand(context.Background(), []string{"--project-root", "."}, io.Discard); err == nil || !strings.Contains(err.Error(), "open fail") {
		t.Fatalf("expected project status open failure, got %v", err)
	}
	if err := projectUnbindCommand(context.Background(), []string{"--project-root", "."}, io.Discard); err == nil || !strings.Contains(err.Error(), "open fail") {
		t.Fatalf("expected project unbind open failure, got %v", err)
	}
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "token"}, nil
	}
	if err := captureCommand(context.Background(), []string{"--name", "captured", "--value", "v"}, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "open fail") {
		t.Fatalf("expected capture open failure, got %v", err)
	}
	ensureSessionAppFn = origEnsureSession
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{}, errors.New("session fail")
	}
	if err := captureCommand(context.Background(), []string{"--name", "captured", "--value", "v"}, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "session fail") {
		t.Fatalf("expected capture session failure, got %v", err)
	}
	ensureSessionAppFn = origEnsureSession
	newVaultStoreFn = func() (*store.Store, error) { return nil, errors.New("store fail") }
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "token"}, nil
	}
	if err := captureCommand(context.Background(), []string{"--name", "captured", "--value", "v"}, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "store fail") {
		t.Fatalf("expected capture store creation failure, got %v", err)
	}
	newVaultStoreFn = func() (*store.Store, error) { return store.New(nil) }
	ensureSessionAppFn = origEnsureSession

	openStoreWithPasswordFn = origOpenStore
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{}, errors.New("session fail")
	}
	if err := executeCommand(context.Background(), []string{"--project-root", ".", "--", "true"}, io.Discard, io.Discard, false, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "session fail") {
		t.Fatalf("expected execute session failure, got %v", err)
	}
	if err := executeCommand(context.Background(), []string{"--bad"}, io.Discard, io.Discard, false, &fakeStarter{}); err == nil {
		t.Fatal("expected execute parse failure")
	}
	if err := executeCommand(context.Background(), []string{"--", "true"}, io.Discard, io.Discard, true, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "inject requires") {
		t.Fatalf("expected inject usage failure, got %v", err)
	}
	if err := writeEnvCommand(context.Background(), []string{"--project-root", ".", "--output", filepath.Join(t.TempDir(), ".env"), "--env", "KEY=secret_01"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "session fail") {
		t.Fatalf("expected write-env session failure, got %v", err)
	}
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "token"}, nil
	}

	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault fail") }
	if err := executeCommand(context.Background(), []string{"--project-root", ".", "--", "true"}, io.Discard, io.Discard, false, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "vault fail") {
		t.Fatalf("expected execute vault failure, got %v", err)
	}
	if err := writeEnvCommand(context.Background(), []string{"--project-root", ".", "--output", filepath.Join(t.TempDir(), ".env"), "--env", "KEY=secret_01"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "vault fail") {
		t.Fatalf("expected write-env vault failure, got %v", err)
	}
	if err := checkRepoCommand(context.Background(), []string{"--project-root", "."}, io.Discard); err == nil || !strings.Contains(err.Error(), "vault fail") {
		t.Fatalf("expected check-repo vault failure, got %v", err)
	}
	if err := tuiCommand(context.Background(), []string{"--project-root", "."}, io.Discard); err == nil || !strings.Contains(err.Error(), "vault fail") {
		t.Fatalf("expected tui vault failure, got %v", err)
	}
	openVaultHandleFn = origOpenVaultHandle

	handle, projectRoot, _ := seedAppVaultHandle(t)
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "token"}, nil
	}
	openVaultHandleFn = func(context.Context) (*store.Handle, error) {
		return handle, nil
	}
	authorizeReferenceAppFn = func(context.Context, *store.Handle, string, string, string, string, store.Operation, store.GrantScope, store.GrantScope, store.GrantScope, time.Duration, string) (store.Item, error) {
		return store.Item{}, errors.New("authorize ref fail")
	}
	if err := executeCommand(context.Background(), []string{"--project-root", projectRoot, "--env", "KEY=secret_01", "--", "true"}, io.Discard, io.Discard, false, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "authorize ref fail") {
		t.Fatalf("expected env authorize failure, got %v", err)
	}
	if err := executeCommand(context.Background(), []string{"--project-root", projectRoot, "--file", "KEY=secret_01", "--", "true"}, io.Discard, io.Discard, true, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "authorize ref fail") {
		t.Fatalf("expected file authorize failure, got %v", err)
	}
	resolveBindingViewAppFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("binding fail")
	}
	if err := executeCommand(context.Background(), []string{"--project-root", projectRoot, "--", "true"}, io.Discard, io.Discard, false, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "binding fail") {
		t.Fatalf("expected execute binding failure, got %v", err)
	}
	resolveBindingViewAppFn = origResolveBindingApp

	authorizeReferenceAppFn = func(context.Context, *store.Handle, string, string, string, string, store.Operation, store.GrantScope, store.GrantScope, store.GrantScope, time.Duration, string) (store.Item, error) {
		return store.Item{Name: "api_token", Value: []byte("abc123")}, nil
	}
	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		autoProtect := false
		return paths.CLIConfig{AutoProtectRepos: &autoProtect}, nil
	}
	unmanagedProjectRoot := t.TempDir()
	if err := executeCommand(context.Background(), []string{"--project-root", unmanagedProjectRoot, "--env", "KEY=secret_01", "--", "true"}, io.Discard, io.Discard, false, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "not managed yet") {
		t.Fatalf("expected execute unmanaged-project failure, got %v", err)
	}
	if err := writeEnvCommand(context.Background(), []string{"--project-root", unmanagedProjectRoot, "--output", filepath.Join(t.TempDir(), ".env"), "--env", "KEY=secret_01"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "not managed yet") {
		t.Fatalf("expected write-env unmanaged-project failure, got %v", err)
	}
	if err := captureCommand(context.Background(), []string{"--name", "captured", "--value", "v", "--project-root", unmanagedProjectRoot, "--grant-project", "window", "--grant-write"}, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "not managed yet") {
		t.Fatalf("expected capture unmanaged-project failure, got %v", err)
	}
	loadCLIConfigAppFn = origLoadCLI
	runnerExecuteFn = func(context.Context, runner.Input) (runner.Result, error) {
		return runner.Result{}, errors.New("runner fail")
	}
	if err := executeCommand(context.Background(), []string{"--project-root", projectRoot, "--env", "KEY=secret_01", "--", "true"}, io.Discard, io.Discard, false, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "runner fail") {
		t.Fatalf("expected runner failure, got %v", err)
	}

	authorizeItemAppFn = func(*store.Handle, string, string, store.Item, store.Operation, store.GrantScope, store.GrantScope, time.Duration) (store.Item, error) {
		return store.Item{}, errors.New("authorize item fail")
	}
	if err := writeEnvCommand(context.Background(), []string{"--project-root", projectRoot, "--output", filepath.Join(t.TempDir(), ".env"), "--env", "KEY=secret_01", "--grant-project", "window", "--grant-convenience", "window"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "authorize item fail") {
		t.Fatalf("expected write-env authorize item failure, got %v", err)
	}
	handle, projectRoot, _ = seedAppVaultHandle(t)
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return handle, nil }
	grantProjectLeaseAppFn = func(*store.Handle, string, string, store.GrantScope, time.Duration) (store.ProjectLease, error) {
		return store.ProjectLease{}, errors.New("grant project fail")
	}
	if err := writeEnvCommand(context.Background(), []string{"--project-root", projectRoot, "--output", filepath.Join(t.TempDir(), ".env"), "--env", "KEY=secret_01", "--grant-project", "window"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "grant project fail") {
		t.Fatalf("expected write-env grant project failure, got %v", err)
	}
	grantProjectLeaseAppFn = origGrantProject
	grantConvenienceAppFn = func(*store.Handle, string, string, string, []string, string, store.GrantScope, time.Duration) (store.ConvenienceGrant, error) {
		return store.ConvenienceGrant{}, errors.New("grant convenience fail")
	}
	if err := writeEnvCommand(context.Background(), []string{"--project-root", projectRoot, "--output", filepath.Join(t.TempDir(), ".env"), "--env", "KEY=secret_01", "--grant-project", "window", "--grant-convenience", "window"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "grant convenience fail") {
		t.Fatalf("expected write-env grant convenience failure, got %v", err)
	}
	grantConvenienceAppFn = origGrantConvenience
	resolveBindingViewAppFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("binding fail")
	}
	if err := writeEnvCommand(context.Background(), []string{"--project-root", projectRoot, "--output", filepath.Join(t.TempDir(), ".env"), "--env", "KEY=secret_01"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "binding fail") {
		t.Fatalf("expected write-env binding failure, got %v", err)
	}
	resolveBindingViewAppFn = origResolveBindingApp
	resolveReferenceExecFn = func(*store.Handle, context.Context, string, string) (store.ResolvedReference, error) {
		return store.ResolvedReference{}, errors.New("resolve ref fail")
	}
	if err := writeEnvCommand(context.Background(), []string{"--project-root", projectRoot, "--output", filepath.Join(t.TempDir(), ".env"), "--env", "KEY=secret_01"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "resolve ref fail") {
		t.Fatalf("expected write-env resolve reference failure, got %v", err)
	}
	resolveReferenceExecFn = origResolveReferenceExec
	getItemExecFn = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("get item fail") }
	if err := writeEnvCommand(context.Background(), []string{"--project-root", projectRoot, "--output", filepath.Join(t.TempDir(), ".env"), "--env", "KEY=secret_01"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "get item fail") {
		t.Fatalf("expected write-env get item failure, got %v", err)
	}
	getItemExecFn = origGetItemExec
	authorizeItemAppFn = origAuthorizeItem
	openWriteEnvFileFn = func(string, int, os.FileMode) (writeEnvFile, error) {
		return nil, errors.New("open file fail")
	}
	if err := writeEnvCommand(context.Background(), []string{"--project-root", projectRoot, "--output", filepath.Join(t.TempDir(), ".env"), "--env", "KEY=secret_01", "--grant-project", "window", "--grant-convenience", "window", "--grant-secret", "session"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "open file fail") {
		t.Fatalf("expected write-env open-file failure, got %v", err)
	}
	openWriteEnvFileFn = func(string, int, os.FileMode) (writeEnvFile, error) {
		return failingWriteEnvFile{err: errors.New("write fail")}, nil
	}
	if err := writeEnvCommand(context.Background(), []string{"--project-root", projectRoot, "--output", filepath.Join(t.TempDir(), ".env"), "--env", "KEY=secret_01", "--grant-project", "window", "--grant-convenience", "window", "--grant-secret", "session"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "write fail") {
		t.Fatalf("expected write-env write failure, got %v", err)
	}
	openWriteEnvFileFn = origOpenWriteEnv

	appCanonicalProjectRootFn = func(context.Context, string) (string, error) { return "", errors.New("canonical fail") }
	if err := sessionOpenCommand(context.Background(), []string{"--project-root", "."}, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "canonical fail") {
		t.Fatalf("expected session open canonical failure, got %v", err)
	}
	if err := checkRepoCommand(context.Background(), []string{"--project-root", "."}, io.Discard); err == nil || !strings.Contains(err.Error(), "canonical fail") {
		t.Fatalf("expected check-repo canonical failure, got %v", err)
	}
	appCanonicalProjectRootFn = origCanonical
	walkProjectDirFn = func(string, fs.WalkDirFunc) error { return errors.New("walk fail") }
	if err := checkRepoCommand(context.Background(), []string{"--project-root", projectRoot}, io.Discard); err == nil || !strings.Contains(err.Error(), "walk fail") {
		t.Fatalf("expected check-repo walk failure, got %v", err)
	}
	walkProjectDirFn = origWalkDir
	walkProjectDirFn = func(root string, fn fs.WalkDirFunc) error {
		return fn(root, nil, errors.New("walk callback fail"))
	}
	if err := checkRepoCommand(context.Background(), []string{"--project-root", projectRoot}, io.Discard); err == nil || !strings.Contains(err.Error(), "walk callback fail") {
		t.Fatalf("expected check-repo walk callback failure, got %v", err)
	}
	walkProjectDirFn = origWalkDir

	resolveBindingViewAppFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("binding fail")
	}
	if err := captureCommand(context.Background(), []string{"--name", "captured", "--value", "v", "--project-root", projectRoot, "--grant-project", "window", "--grant-write"}, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "binding fail") {
		t.Fatalf("expected capture binding failure, got %v", err)
	}
	resolveBindingViewAppFn = origResolveBindingApp
	getItemAppFn = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("get item fail") }
	if err := captureCommand(context.Background(), []string{"--name", "captured", "--value", "v", "--project-root", projectRoot, "--grant-project", "window", "--grant-write"}, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "get item fail") {
		t.Fatalf("expected capture get-item failure, got %v", err)
	}
	getItemAppFn = origGetItemSecrets
	authorizeCaptureFn = func(context.Context, *store.Handle, string, string, string, store.GrantScope, store.GrantScope, time.Duration, bool) error {
		return errors.New("authorize capture fail")
	}
	if err := captureCommand(context.Background(), []string{"--name", "captured", "--value", "v", "--project-root", projectRoot, "--grant-project", "window", "--grant-write"}, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "authorize capture fail") {
		t.Fatalf("expected capture authorize failure, got %v", err)
	}
	absPathExecFn = func(string) (string, error) { return "", errors.New("abs fail") }
	if pathInsideProject(projectRoot, projectRoot) {
		t.Fatal("expected pathInsideProject to fail closed on abs error")
	}
	absPathExecFn = origAbs
	if pathInsideProject(projectRoot, "") {
		t.Fatal("expected empty root to fail closed")
	}
}

func seedAppVaultHandle(t *testing.T) (*store.Handle, string, string) {
	t.Helper()
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	vaultStore, err := store.New(nil)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token"}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	return handle, projectRoot, filepath.Join(homeDir, "vault.json.enc")
}

type failingWriteEnvFile struct {
	err error
}

func (f failingWriteEnvFile) WriteString(string) (int, error) { return 0, f.err }

func (f failingWriteEnvFile) Close() error { return nil }

func TestDirectResidualAppBranches(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	projectRoot := t.TempDir()
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("API_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	if err := projectBindCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected project bind parse error")
	}
	corruptHandle, _, statePath := seedAppVaultHandle(t)
	if err := os.WriteFile(statePath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("corrupt state file: %v", err)
	}
	origOpenStore := openStoreWithPasswordFn
	openStoreWithPasswordFn = func(context.Context, *store.Store, string) (*store.Handle, error) { return corruptHandle, nil }
	if err := projectBindCommand(context.Background(), []string{"--project-root", projectRoot, "--hooks=false"}, io.Discard); err == nil {
		t.Fatal("expected project bind persist error")
	}
	if err := projectUnbindCommand(context.Background(), []string{"--project-root", projectRoot}, io.Discard); err == nil {
		t.Fatal("expected project unbind persist error")
	}
	openStoreWithPasswordFn = origOpenStore
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	manifestPath := filepath.Join(projectRoot, ".hasp.manifest.json")
	if err := os.WriteFile(manifestPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write malformed manifest: %v", err)
	}
	if err := projectStatusCommand(context.Background(), []string{"--project-root", projectRoot}, io.Discard); err == nil {
		t.Fatal("expected project status manifest decode error")
	}

	t.Setenv("HASP_MASTER_PASSWORD", "")
	if err := importCommand(context.Background(), []string{envPath}, io.Discard); err == nil {
		t.Fatal("expected importCommand missing-password error")
	}
	if err := setCommand(context.Background(), []string{"--name", "api_token", "--value", "abc123"}, io.Discard); err == nil {
		t.Fatal("expected setCommand missing-password error")
	}
	if err := redactCommand(context.Background(), bytes.NewBufferString("secret"), io.Discard); err == nil {
		t.Fatal("expected redactCommand missing-password error")
	}

	origEnsureSession := ensureSessionAppFn
	defer func() { ensureSessionAppFn = origEnsureSession }()
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "token"}, nil
	}
	if err := captureCommand(context.Background(), []string{"--name", "captured", "--value", "v", "--project-root", projectRoot, "--grant-project", "window", "--grant-write"}, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected captureCommand missing-password error")
	}

	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"set", "--name", "empty", "--value", ""}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set empty value item: %v", err)
	}
	if err := writeEnvCommand(context.Background(), []string{"--output", filepath.Join(t.TempDir(), ".env")}, io.Discard, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected write-env usage error")
	}
	outputDir := filepath.Join(t.TempDir(), "dir")
	if err := os.Mkdir(outputDir, 0o755); err != nil {
		t.Fatalf("mkdir output dir: %v", err)
	}
	if err := writeEnvCommand(context.Background(), []string{"--project-root", projectRoot, "--output", outputDir, "--env", "KEY=secret_01", "--grant-project", "window", "--grant-secret", "session", "--grant-convenience", "window"}, io.Discard, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected write-env open failure")
	}

	var checkOut bytes.Buffer
	if err := checkRepoCommand(context.Background(), []string{"--project-root", projectRoot, "--allow-managed-secrets"}, &checkOut); err != nil {
		t.Fatalf("check-repo allow managed secrets: %v", err)
	}
	if !strings.Contains(checkOut.String(), "\"override\":true") {
		t.Fatalf("expected override payload, got %q", checkOut.String())
	}

	if pathInsideProject("bad\x00path", projectRoot) {
		t.Fatal("expected bad path to be outside project")
	}
	if pathInsideProject(projectRoot, "bad\x00root") {
		t.Fatal("expected bad root to fail closed")
	}
}
