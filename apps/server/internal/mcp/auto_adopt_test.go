package mcp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestMCPAutoAdoptHelpers(t *testing.T) {
	lockMCPSeams(t)
	origLoadCLI := loadCLIConfigMCPFn
	origResolveBinding := resolveBindingViewMCPFn
	origCanonical := canonicalProjectRootMCPFn
	defer func() {
		loadCLIConfigMCPFn = origLoadCLI
		resolveBindingViewMCPFn = origResolveBinding
		canonicalProjectRootMCPFn = origCanonical
	}()

	t.Run("loadProjectDefaultsMCP", func(t *testing.T) {
		loadCLIConfigMCPFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, nil }
		defaults, err := loadProjectDefaultsMCP()
		if err != nil {
			t.Fatalf("load default config: %v", err)
		}
		if !defaults.AutoProtectRepos || !defaults.AutoInstallHooks || defaults.DefaultPolicy != store.PolicySession {
			t.Fatalf("unexpected defaults: %+v", defaults)
		}

		enabled := true
		disabled := false
		loadCLIConfigMCPFn = func() (paths.CLIConfig, error) {
			return paths.CLIConfig{
				AutoProtectRepos:     &disabled,
				AutoInstallHooks:     &enabled,
				DefaultCapturePolicy: string(store.PolicyAccess),
			}, nil
		}
		overridden, err := loadProjectDefaultsMCP()
		if err != nil {
			t.Fatalf("load overridden config: %v", err)
		}
		if overridden.AutoProtectRepos || !overridden.AutoInstallHooks || overridden.DefaultPolicy != store.PolicyAccess {
			t.Fatalf("unexpected overridden defaults: %+v", overridden)
		}

		loadCLIConfigMCPFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, errors.New("load fail") }
		if _, err := loadProjectDefaultsMCP(); err == nil || !strings.Contains(err.Error(), "load fail") {
			t.Fatalf("expected config load failure, got %v", err)
		}
	})

	t.Run("pathLooksLikeGitRepoMCP", func(t *testing.T) {
		if pathLooksLikeGitRepoMCP("") {
			t.Fatal("expected empty root to be false")
		}
		root := t.TempDir()
		if pathLooksLikeGitRepoMCP(root) {
			t.Fatal("expected root without .git to be false")
		}
		if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
			t.Fatalf("mkdir .git: %v", err)
		}
		if !pathLooksLikeGitRepoMCP(root) {
			t.Fatal("expected .git dir to be detected")
		}
		fileRoot := t.TempDir()
		if err := os.WriteFile(filepath.Join(fileRoot, ".git"), []byte("gitdir: elsewhere\n"), 0o600); err != nil {
			t.Fatalf("write .git file: %v", err)
		}
		if !pathLooksLikeGitRepoMCP(fileRoot) {
			t.Fatal("expected .git file to be detected")
		}
	})

	t.Run("cloneAliasSetMCP and requireProjectBindingMCP", func(t *testing.T) {
		clonedEmpty := cloneAliasSetMCP(nil)
		if len(clonedEmpty) != 0 {
			t.Fatalf("expected empty clone, got %+v", clonedEmpty)
		}
		source := map[string]string{"secret_01": "api_token"}
		cloned := cloneAliasSetMCP(source)
		cloned["secret_02"] = "db_url"
		if len(source) != 1 {
			t.Fatalf("expected source map to stay unchanged, got %+v", source)
		}
		if err := requireProjectBindingMCP(store.Binding{ID: "binding"}, "/tmp/project"); err != nil {
			t.Fatalf("expected existing binding to pass, got %v", err)
		}
		if err := requireProjectBindingMCP(store.Binding{}, "/tmp/project"); err == nil || !strings.Contains(err.Error(), "not managed yet") {
			t.Fatalf("expected missing binding error, got %v", err)
		}
	})
}

func TestEnsureProjectBindingMCP(t *testing.T) {
	lockMCPSeams(t)
	origLoadCLI := loadCLIConfigMCPFn
	origResolveBinding := resolveBindingViewMCPFn
	origCanonical := canonicalProjectRootMCPFn
	defer func() {
		loadCLIConfigMCPFn = origLoadCLI
		resolveBindingViewMCPFn = origResolveBinding
		canonicalProjectRootMCPFn = origCanonical
	}()

	homeDir := t.TempDir()
	t.Setenv(paths.EnvHome, homeDir)
	vaultStore, err := store.New(nil)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "secret-password"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "secret-password")
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}

	projectRoot := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("mkdir project root: %v", err)
	}
	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) {
		return paths.CLIConfig{DefaultCapturePolicy: string(store.PolicyAccess)}, nil
	}
	binding, visible, err := ensureProjectBindingMCP(context.Background(), handle, projectRoot)
	if err != nil {
		t.Fatalf("auto adopt binding: %v", err)
	}
	if binding.ID != "" || len(visible) != 0 {
		t.Fatalf("expected non-git path to stay unmanaged, got %+v visible=%+v", binding, visible)
	}
	if binding.DefaultCapturePolicy != "" || binding.HookInstalled {
		t.Fatalf("unexpected unmanaged binding properties: %+v", binding)
	}
	again, visibleAgain, err := ensureProjectBindingMCP(context.Background(), handle, projectRoot)
	if err != nil {
		t.Fatalf("re-resolve adopted binding: %v", err)
	}
	if again.ID != "" || len(visibleAgain) != 0 {
		t.Fatalf("expected stable unmanaged binding on second resolve, got %+v visible=%+v", again, visibleAgain)
	}

	gitRoot := filepath.Join(t.TempDir(), "git-project")
	if err := os.MkdirAll(gitRoot, 0o755); err != nil {
		t.Fatalf("mkdir git root: %v", err)
	}
	if out, err := initTestGitRepo(gitRoot); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	binding, visible, err = ensureProjectBindingMCP(context.Background(), handle, gitRoot)
	if err != nil {
		t.Fatalf("auto adopt git binding: %v", err)
	}
	if binding.ID == "" || len(visible) != 0 {
		t.Fatalf("unexpected git binding view: %+v visible=%+v", binding, visible)
	}
	if binding.DefaultCapturePolicy != store.PolicyAccess || !binding.HookInstalled {
		t.Fatalf("unexpected adopted git binding properties: %+v", binding)
	}

	disabled := false
	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) {
		return paths.CLIConfig{AutoProtectRepos: &disabled}, nil
	}
	emptyBinding, emptyVisible, err := ensureProjectBindingMCP(context.Background(), handle, filepath.Join(t.TempDir(), "unmanaged"))
	if err != nil {
		t.Fatalf("disabled auto-protect binding lookup: %v", err)
	}
	if emptyBinding.ID != "" || len(emptyVisible) != 0 {
		t.Fatalf("expected unmanaged empty binding, got %+v visible=%+v", emptyBinding, emptyVisible)
	}

	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, errors.New("load fail") }
	if _, _, err := ensureProjectBindingMCP(context.Background(), handle, filepath.Join(t.TempDir(), "load-fail")); err == nil || !strings.Contains(err.Error(), "load fail") {
		t.Fatalf("expected config load failure, got %v", err)
	}

	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, nil }
	canonicalProjectRootMCPFn = func(context.Context, string) (string, error) { return "", errors.New("canonical fail") }
	if _, _, err := ensureProjectBindingMCP(context.Background(), handle, filepath.Join(t.TempDir(), "canonical-fail")); err == nil || !strings.Contains(err.Error(), "canonical fail") {
		t.Fatalf("expected canonical failure, got %v", err)
	}
	canonicalProjectRootMCPFn = origCanonical

	resolveBindingViewMCPFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("binding fail")
	}
	if _, _, err := ensureProjectBindingMCP(context.Background(), handle, filepath.Join(t.TempDir(), "binding-fail")); err == nil || !strings.Contains(err.Error(), "binding fail") {
		t.Fatalf("expected resolve binding failure, got %v", err)
	}
	resolveBindingViewMCPFn = origResolveBinding

	blockedHome := t.TempDir()
	t.Setenv(paths.EnvHome, blockedHome)
	blockedStore, err := store.New(nil)
	if err != nil {
		t.Fatalf("new blocked store: %v", err)
	}
	if err := blockedStore.Init(context.Background(), "secret-password"); err != nil {
		t.Fatalf("init blocked store: %v", err)
	}
	blockedHandle, err := blockedStore.OpenWithPassword(context.Background(), "secret-password")
	if err != nil {
		t.Fatalf("open blocked handle: %v", err)
	}
	if err := os.Chmod(blockedHome, 0o500); err != nil {
		t.Fatalf("chmod blocked home: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blockedHome, 0o700) })
	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, nil }
	persistRoot := filepath.Join(t.TempDir(), "persist-fail")
	if err := os.MkdirAll(persistRoot, 0o755); err != nil {
		t.Fatalf("mkdir persist root: %v", err)
	}
	if out, err := initTestGitRepo(persistRoot); err != nil {
		t.Fatalf("git init persist root: %v: %s", err, out)
	}
	if _, _, err := ensureProjectBindingMCP(context.Background(), blockedHandle, persistRoot); err == nil {
		t.Fatal("expected upsert binding persist failure")
	}
}

func TestMCPAutoAdoptResidualBranches(t *testing.T) {
	lockMCPSeams(t)
	origLoadCLI := loadCLIConfigMCPFn
	origEnsureSession := ensureSessionFn
	origGetItem := getItemMCPFn
	defer func() {
		loadCLIConfigMCPFn = origLoadCLI
		ensureSessionFn = origEnsureSession
		getItemMCPFn = origGetItem
	}()

	homeDir := t.TempDir()
	t.Setenv(paths.EnvHome, homeDir)
	vaultStore, err := store.New(nil)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "secret-password"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "secret-password")
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}

	disabled := false
	projectRoot := filepath.Join(t.TempDir(), "unmanaged")
	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) {
		return paths.CLIConfig{AutoProtectRepos: &disabled}, nil
	}
	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "token"}, nil
	}

	if _, err := callList(context.Background(), handle, toolCall{Name: "hasp_list", Arguments: map[string]any{"project_root": projectRoot}}); err == nil || !strings.Contains(err.Error(), "not managed yet") {
		t.Fatalf("expected callList unmanaged-project error, got %v", err)
	}
	if _, err := callExecute(context.Background(), handle, toolCall{Name: "hasp_run", Arguments: map[string]any{"project_root": projectRoot, "command": []any{"true"}}}); err == nil || !strings.Contains(err.Error(), "not managed yet") {
		t.Fatalf("expected callExecute unmanaged-project error, got %v", err)
	}
	getItemMCPFn = func(*store.Handle, string) (store.Item, error) { return store.Item{}, store.ErrItemNotFound }
	if _, err := callCapture(context.Background(), handle, toolCall{Name: "hasp_capture", Arguments: map[string]any{"project_root": projectRoot, "name": "captured"}}); err == nil || !strings.Contains(err.Error(), "not managed yet") {
		t.Fatalf("expected callCapture unmanaged-project error, got %v", err)
	}

	loadCLIConfigMCPFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, errors.New("load fail") }
	if _, err := callCheck(context.Background(), handle, toolCall{Name: "hasp_check", Arguments: map[string]any{"project_root": projectRoot}}); err == nil || !strings.Contains(err.Error(), "load fail") {
		t.Fatalf("expected callCheck ensure-binding failure, got %v", err)
	}
}
