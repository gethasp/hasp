package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type setupErrReader struct{}

func (setupErrReader) Read(_ []byte) (int, error) { return 0, errors.New("read fail") }

func TestNewSetupPrompterDefaults(t *testing.T) {
	prompt := newSetupPrompter(nil, nil)
	if prompt.reader == nil || prompt.out == nil {
		t.Fatal("expected default prompt reader and writer")
	}
}

func TestSetupResolveHomeBranches(t *testing.T) {
	lockAppSeams(t)
	userHome := t.TempDir()
	configHome := t.TempDir()
	t.Setenv("HOME", userHome)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv(paths.EnvHome, "")

	origHome := setupUserHomeDirFn
	origTempDir := setupTempDirFn
	defer func() {
		setupUserHomeDirFn = origHome
		setupTempDirFn = origTempDir
	}()
	setupUserHomeDirFn = func() (string, error) { return "", errors.New("no home") }
	setupTempDirFn = func() string { return filepath.Join(t.TempDir(), "different-temp-root") }

	resolved, _, err := setupResolveHome(setupOptions{HaspHome: "."}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard))
	if err != nil || !filepath.IsAbs(resolved) {
		t.Fatalf("expected explicit absolute home, got %q err=%v", resolved, err)
	}

	savedHome := filepath.Join(configHome, "saved-home")
	if err := os.MkdirAll(savedHome, 0o700); err != nil {
		t.Fatalf("mkdir saved config home: %v", err)
	}
	if err := paths.SaveConfig(paths.CLIConfig{HomeDir: savedHome}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	resolved, _, err = setupResolveHome(setupOptions{NonInteractive: true}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard))
	if err != nil || resolved != savedHome {
		t.Fatalf("expected saved config home, got %q err=%v", resolved, err)
	}

	if err := paths.SaveConfig(paths.CLIConfig{HomeDir: filepath.Join(configHome, "missing-home")}); err != nil {
		t.Fatalf("save missing config home: %v", err)
	}
	resolved, _, err = setupResolveHome(setupOptions{NonInteractive: true}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard))
	if err != nil || resolved != ".hasp" {
		t.Fatalf("expected stale saved home to fall back, got %q err=%v", resolved, err)
	}

	setupUserHomeDirFn = func() (string, error) { return userHome, nil }
	resolved, _, err = setupResolveHome(setupOptions{}, newSetupPrompter(bytes.NewBufferString("~/custom\n"), io.Discard))
	if err != nil || resolved != filepath.Join(userHome, "custom") {
		t.Fatalf("expected prompted custom home, got %q err=%v", resolved, err)
	}
}

func TestDefaultSetupHomeFallbackToPathsResolve(t *testing.T) {
	lockAppSeams(t)
	origHome := setupUserHomeDirFn
	defer func() { setupUserHomeDirFn = origHome }()
	setupUserHomeDirFn = func() (string, error) { return "", errors.New("boom") }
	if got := defaultSetupHome(); got == "" {
		t.Fatal("expected fallback default home")
	}
}

func TestSetupResolveProjectRootInteractiveAndError(t *testing.T) {
	lockAppSeams(t)
	repo := t.TempDir()
	if out, err := run("git", "-C", repo, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	root, err := setupResolveProjectRoot(context.Background(), setupOptions{}, newSetupPrompter(bytes.NewBufferString(repo+"\n"), io.Discard))
	if err != nil || root == "" {
		t.Fatalf("interactive project root = %q err=%v", root, err)
	}
}

func TestSetupResolveBoolOptionsExistingConfigAndImportPrompt(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	origHome := setupUserHomeDirFn
	defer func() { setupUserHomeDirFn = origHome }()
	setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
	if err := os.WriteFile(filepath.Join(homeDir, ".claude.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	opts := setupOptions{}
	opts.Repo = t.TempDir()
	prompt := newSetupPrompter(bytes.NewBufferString("y\nn\ny\ny\n/path/to/import.env\ny\ny\n"), io.Discard)
	agents := []setupAgentSpec{{ID: "claude-code", Format: "json", ConfigPath: func(string) string { return filepath.Join(homeDir, ".claude.json") }}}
	if err := setupResolveBoolOptions(&opts, prompt, agents); err != nil {
		t.Fatalf("resolve bool options: %v", err)
	}
	if opts.ImportPath != "/path/to/import.env" || !opts.BindImports {
		t.Fatalf("expected prompted import+bind, got %+v", opts)
	}
	if !opts.OverwriteExistingConfig.set || !opts.OverwriteExistingConfig.value {
		t.Fatalf("expected prompted overwrite approval, got %+v", opts.OverwriteExistingConfig)
	}
}

func TestSetupResolvePasswordErrorBranches(t *testing.T) {
	lockAppSeams(t)
	if _, _, err := setupResolvePassword(newSetupPrompter(bytes.NewBuffer(nil), io.Discard), setupOptions{PasswordEnv: "EMPTY"}, t.TempDir()); err == nil {
		t.Fatal("expected empty password env error")
	}
	if _, _, err := setupResolvePassword(newSetupPrompter(bytes.NewBuffer(nil), io.Discard), setupOptions{NonInteractive: true}, t.TempDir()); err == nil {
		t.Fatal("expected missing non-interactive password source error")
	}
	if _, _, err := setupResolvePassword(newSetupPrompter(bytes.NewBufferString(""), io.Discard), setupOptions{PasswordStdin: true}, t.TempDir()); err == nil {
		t.Fatal("expected empty stdin password error")
	}
}

func TestSetupEnsureHandleExistingVault(t *testing.T) {
	lockAppSeams(t)
	home := t.TempDir()
	t.Setenv("HASP_HOME", home)
	keyring := &memorySetupKeyring{}
	vaultStore, err := store.New(keyring)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, state, err := setupEnsureHandle(context.Background(), vaultStore, "correct horse battery staple", true, false)
	if err != nil || handle == nil || state != "existing" {
		t.Fatalf("ensure existing handle state=%q err=%v", state, err)
	}
}

func TestSetupImportInputAndAliases(t *testing.T) {
	lockAppSeams(t)
	home := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HASP_HOME", home)
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
	if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	input := setupImportInput(newSetupPrompter(bytes.NewBufferString("OPENAI_API_KEY=abc123"), io.Discard), setupOptions{ImportPath: "-"})
	if input == nil {
		t.Fatal("expected stdin import input")
	}
	imported, err := setupImportAndBind(context.Background(), handle, projectRoot, setupOptions{
		Aliases: map[string]string{"secret_01": "api_token"},
	}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard))
	if err != nil {
		t.Fatalf("import and bind aliases only: %v", err)
	}
	if len(imported) != 0 {
		t.Fatalf("expected no imported records, got %+v", imported)
	}
}

func TestSetupWriteAgentConfigsInvalidFormatAndNoop(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	specs := []setupAgentSpec{{
		ID:     "bad",
		Format: "yaml",
		ConfigPath: func(string) string {
			return filepath.Join(homeDir, "bad.yaml")
		},
	}}
	if _, err := setupWriteAgentConfigs(specs, ""); err == nil {
		t.Fatal("expected invalid format error")
	}

	path := filepath.Join(homeDir, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	origLook := setupLookPathFn
	origExec := setupExecutableFn
	defer func() {
		setupLookPathFn = origLook
		setupExecutableFn = origExec
	}()
	setupLookPathFn = func(string) (string, error) { return "/bin/hasp", nil }
	setupExecutableFn = func() (string, error) { return "/bin/hasp", nil }
	haspHome := filepath.Join(homeDir, ".hasp")
	wrapperPath := filepath.Join(haspHome, "bin", "hasp-agent-cursor")
	data, err := upsertJSONMCPServerConfig(nil, haspHome, wrapperPath, "cursor")
	if err != nil {
		t.Fatalf("upsert json config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	outcomes, err := setupWriteAgentConfigs([]setupAgentSpec{{
		ID:     "cursor",
		Format: "json",
		ConfigPath: func(string) string {
			return path
		},
	}}, haspHome)
	if err != nil {
		t.Fatalf("write agent configs noop: %v", err)
	}
	if outcomes[0].Changed {
		t.Fatalf("expected noop config write, got %+v", outcomes)
	}
}

func TestSetupAtomicWriteAndPromptErrors(t *testing.T) {
	lockAppSeams(t)
	path := filepath.Join(t.TempDir(), "file.txt")
	if _, _, err := setupAtomicWrite(path, nil, []byte("new")); err != nil {
		t.Fatalf("atomic write create: %v", err)
	}

	origCreateTemp := setupCreateTempFn
	defer func() { setupCreateTempFn = origCreateTemp }()
	setupCreateTempFn = func(string, string) (*os.File, error) { return nil, errors.New("create temp fail") }
	if _, _, err := setupAtomicWrite(filepath.Join(t.TempDir(), "other.txt"), nil, []byte("new")); err == nil {
		t.Fatal("expected temp file creation error")
	}

	if _, err := promptString(newSetupPrompter(setupErrReader{}, io.Discard), "label", "default"); err == nil {
		t.Fatal("expected prompt string read error")
	}
	if value, err := promptBool(newSetupPrompter(bytes.NewBufferString("maybe\n"), io.Discard), "label", true); err != nil || !value {
		t.Fatalf("expected invalid bool answer to fall back to default, got %v err=%v", value, err)
	}
}

func TestPromptPasswordHiddenBranchAndSetEnv(t *testing.T) {
	lockAppSeams(t)
	temp, err := os.CreateTemp(t.TempDir(), "tty-sim")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer temp.Close()
	if _, err := temp.WriteString("hidden\n"); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if _, err := temp.Seek(0, 0); err != nil {
		t.Fatalf("seek temp file: %v", err)
	}
	prompt := newSetupPrompter(temp, io.Discard)
	origCanHide := setupCanHideInputFn
	origStty := setupSttyFn
	defer func() {
		setupCanHideInputFn = origCanHide
		setupSttyFn = origStty
	}()
	setupCanHideInputFn = func(*os.File) bool { return true }
	setupSttyFn = func(_ *os.File, _ ...string) error { return nil }
	password, err := promptPassword(prompt, "hidden")
	if err != nil || password != "hidden" {
		t.Fatalf("hidden prompt password = %q err=%v", password, err)
	}

	restore, err := setupSetEnv("HASP_SETUP_TEMP", "value")
	if err != nil {
		t.Fatalf("set env: %v", err)
	}
	if os.Getenv("HASP_SETUP_TEMP") != "value" {
		t.Fatal("expected temporary env value")
	}
	restore()
	if os.Getenv("HASP_SETUP_TEMP") != "" {
		t.Fatal("expected env restore cleanup")
	}
}

func TestRunSetupErrorSeams(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	keyring := &memorySetupKeyring{}

	origNewStore := newVaultStoreFn
	origHome := setupUserHomeDirFn
	origLookPath := setupLookPathFn
	origSave := setupSaveConfigFn
	origCanon := setupCanonicalProjectRoot
	origResolvePassword := setupResolvePasswordFn
	origSetEnv := setupSetEnvFn
	origImportBind := setupImportAndBindFn
	origFinalize := setupFinalizeBindingFn
	origWriteAgents := setupWriteAgentConfigsFn
	origVerifyHarness := setupVerifyHarnessFn
	defer func() {
		newVaultStoreFn = origNewStore
		setupUserHomeDirFn = origHome
		setupLookPathFn = origLookPath
		setupSaveConfigFn = origSave
		setupCanonicalProjectRoot = origCanon
		setupResolvePasswordFn = origResolvePassword
		setupSetEnvFn = origSetEnv
		setupImportAndBindFn = origImportBind
		setupFinalizeBindingFn = origFinalize
		setupWriteAgentConfigsFn = origWriteAgents
		setupVerifyHarnessFn = origVerifyHarness
	}()

	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }
	setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
	setupLookPathFn = func(name string) (string, error) {
		if name == "codex" {
			return "/usr/bin/codex", nil
		}
		return "", os.ErrNotExist
	}
	t.Setenv("HOME", homeDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))

	baseOpts := setupOptions{
		NonInteractive:          true,
		HaspHome:                filepath.Join(homeDir, ".hasp"),
		Repo:                    projectRoot,
		Agents:                  setupAgentFlags{"codex-cli"},
		PasswordEnv:             "SETUP_PW",
		InstallHooks:            setupOptionalBool{set: true, value: false},
		EnableConvenienceUnlock: setupOptionalBool{set: true, value: false},
		OverwriteExistingConfig: setupOptionalBool{set: true, value: true},
	}
	t.Setenv("SETUP_PW", "correct horse battery staple")

	setupSaveConfigFn = func(paths.CLIConfig) error { return errors.New("save fail") }
	if _, err := runSetup(context.Background(), baseOpts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "save fail") {
		t.Fatalf("expected save config failure, got %v", err)
	}
	setupSaveConfigFn = origSave

	setupSetEnvFn = func(string, string) (func(), error) { return nil, errors.New("setenv fail") }
	if _, err := runSetup(context.Background(), baseOpts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "setenv fail") {
		t.Fatalf("expected set env failure, got %v", err)
	}
	setupSetEnvFn = origSetEnv

	newVaultStoreFn = func() (*store.Store, error) { return nil, errors.New("store fail") }
	if _, err := runSetup(context.Background(), baseOpts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "store fail") {
		t.Fatalf("expected store fail, got %v", err)
	}
	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }

	setupResolvePasswordFn = func(*setupPrompter, setupOptions, string) (string, bool, error) {
		return "", false, errors.New("password fail")
	}
	if _, err := runSetup(context.Background(), baseOpts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "password fail") {
		t.Fatalf("expected password fail, got %v", err)
	}
	setupResolvePasswordFn = origResolvePassword

	setupImportAndBindFn = func(context.Context, *store.Handle, string, setupOptions, *setupPrompter) ([]store.ImportedItem, error) {
		return nil, errors.New("import fail")
	}
	if _, err := runSetup(context.Background(), baseOpts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "import fail") {
		t.Fatalf("expected import fail, got %v", err)
	}
	setupImportAndBindFn = origImportBind

	setupFinalizeBindingFn = func(context.Context, *store.Handle, string, setupOptions) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("finalize fail")
	}
	if _, err := runSetup(context.Background(), baseOpts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "finalize fail") {
		t.Fatalf("expected finalize fail, got %v", err)
	}
	setupFinalizeBindingFn = origFinalize

	setupWriteAgentConfigsFn = func([]setupAgentSpec, string) ([]setupAgentOutcome, error) {
		return nil, errors.New("agent write fail")
	}
	if _, err := runSetup(context.Background(), baseOpts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "agent write fail") {
		t.Fatalf("expected agent write fail, got %v", err)
	}
	setupWriteAgentConfigsFn = origWriteAgents

	setupVerifyHarnessFn = func(context.Context, []setupAgentSpec) (map[string]any, error) {
		return nil, errors.New("verify fail")
	}
	if _, err := runSetup(context.Background(), baseOpts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "verify fail") {
		t.Fatalf("expected verify fail, got %v", err)
	}
}

func TestSetupAtomicWriteAdditionalFailuresAndHarnessBranches(t *testing.T) {
	lockAppSeams(t)

	path := filepath.Join(t.TempDir(), "file.txt")
	origCreateTemp := setupCreateTempFn
	origWrite := setupTempWriteFn
	origChmod := setupTempChmodFn
	origClose := setupTempCloseFn
	origServe := setupMCPServeFn
	origTools := setupMCPToolNamesFn
	defer func() {
		setupCreateTempFn = origCreateTemp
		setupTempWriteFn = origWrite
		setupTempChmodFn = origChmod
		setupTempCloseFn = origClose
		setupMCPServeFn = origServe
		setupMCPToolNamesFn = origTools
	}()

	tmpDir := t.TempDir()
	setupCreateTempFn = func(dir, pattern string) (*os.File, error) {
		return os.CreateTemp(tmpDir, pattern)
	}
	setupTempWriteFn = func(*os.File, []byte) (int, error) { return 0, errors.New("write fail") }
	if _, _, err := setupAtomicWrite(path, nil, []byte("x")); err == nil {
		t.Fatal("expected temp write failure")
	}

	setupTempWriteFn = origWrite
	setupTempChmodFn = func(*os.File, os.FileMode) error { return errors.New("chmod fail") }
	if _, _, err := setupAtomicWrite(path, nil, []byte("x")); err == nil {
		t.Fatal("expected temp chmod failure")
	}

	setupTempChmodFn = origChmod
	setupTempCloseFn = func(*os.File) error { return errors.New("close fail") }
	if _, _, err := setupAtomicWrite(path, nil, []byte("x")); err == nil {
		t.Fatal("expected temp close failure")
	}

	setupMCPServeFn = func(context.Context, io.Reader, io.Writer) error { return errors.New("serve fail") }
	if _, err := setupVerifyHarness(context.Background(), nil); err == nil {
		t.Fatal("expected setup verify harness serve failure")
	}

	setupMCPServeFn = func(_ context.Context, _ io.Reader, w io.Writer) error {
		_, err := io.WriteString(w, "{\"result\":[]}\n")
		return err
	}
	setupMCPToolNamesFn = func() []string { return nil }
	if _, err := setupVerifyHarness(context.Background(), nil); err == nil {
		t.Fatal("expected setup verify harness missing tools failure")
	}
}

func TestSetupExtraBranchCoverage(t *testing.T) {
	lockAppSeams(t)

	if err := setupCommand(context.Background(), []string{"--install-hooks=maybe"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected setup parse failure")
	}

	if _, err := promptString(newSetupPrompter(bytes.NewBufferString("x"), errWriter{err: errors.New("write fail")}), "label", "default"); err == nil {
		t.Fatal("expected prompt string writer failure")
	}
	if _, err := promptBool(newSetupPrompter(setupErrReader{}, io.Discard), "label", false); err == nil {
		t.Fatal("expected prompt bool read failure")
	}
	if _, err := promptPassword(newSetupPrompter(bytes.NewBufferString("x"), errWriter{err: errors.New("write fail")}), "pw"); err == nil {
		t.Fatal("expected prompt password writer failure")
	}
	if _, err := setupSetEnv("bad=name", "value"); err == nil {
		t.Fatal("expected invalid env name error")
	}
	if _, err := upsertJSONMCPServerConfig([]byte(`{bad`), "", "/bin/hasp", "cursor"); err == nil {
		t.Fatal("expected invalid JSON error")
	}
}
