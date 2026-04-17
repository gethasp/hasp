package app

import (
	"bufio"
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

func TestSetupOptionalBoolAndAgentFlags(t *testing.T) {
	var opt setupOptionalBool
	if opt.String() != "" {
		t.Fatalf("expected empty unset bool string, got %q", opt.String())
	}
	if err := opt.Set("yes"); err != nil {
		t.Fatalf("set bool true: %v", err)
	}
	if !opt.value || opt.String() != "true" {
		t.Fatalf("unexpected bool state: %+v", opt)
	}
	if err := opt.Set("no"); err != nil {
		t.Fatalf("set bool false: %v", err)
	}
	if opt.value || opt.String() != "false" {
		t.Fatalf("unexpected bool false state: %+v", opt)
	}
	if err := opt.Set("maybe"); err == nil {
		t.Fatal("expected invalid bool error")
	}

	var agents setupAgentFlags
	if agents.String() != "" {
		t.Fatalf("expected empty agent flags string, got %q", agents.String())
	}
	if err := agents.Set("codex-cli, claude-code"); err != nil {
		t.Fatalf("set agents: %v", err)
	}
	if got := agents.String(); got != "codex-cli,claude-code" {
		t.Fatalf("unexpected agents string: %q", got)
	}
}

func TestParseSetupOptionsAndValidation(t *testing.T) {
	if _, err := parseSetupOptions([]string{"--master-password-env", "A", "--master-password-stdin"}); err == nil {
		t.Fatal("expected conflicting password source error")
	}
	if _, err := parseSetupOptions([]string{"extra"}); err == nil {
		t.Fatal("expected usage error for trailing args")
	}

	opts, err := parseSetupOptions([]string{
		"--non-interactive",
		"--hasp-home", "/tmp/hasp-home",
		"--repo", "/tmp/repo",
		"--agent", "codex-cli",
		"--master-password-env", "PW",
		"--install-hooks=false",
		"--enable-convenience-unlock=false",
	})
	if err != nil {
		t.Fatalf("parse setup options: %v", err)
	}
	if err := validateSetupNonInteractive(opts); err != nil {
		t.Fatalf("validate non-interactive options: %v", err)
	}
	if err := validateSetupNonInteractive(setupOptions{NonInteractive: true}); err == nil {
		t.Fatal("expected missing non-interactive fields error")
	}
}

func TestDefaultSetupHomeAndExpandHome(t *testing.T) {
	lockAppSeams(t)
	origHome := setupUserHomeDirFn
	defer func() { setupUserHomeDirFn = origHome }()
	setupUserHomeDirFn = func() (string, error) { return "/tmp/setup-home-user", nil }
	if got := defaultSetupHome(); got != "/tmp/setup-home-user/.hasp" {
		t.Fatalf("default home = %q", got)
	}
	expanded, err := expandHome("~/vault")
	if err != nil {
		t.Fatalf("expand home: %v", err)
	}
	if expanded != "/tmp/setup-home-user/vault" {
		t.Fatalf("expanded home = %q", expanded)
	}
}

func TestSetupResolveHomeAndProjectRoot(t *testing.T) {
	lockAppSeams(t)
	configHome := t.TempDir()
	userHome := t.TempDir()
	repo := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("HOME", userHome)

	origHome := setupUserHomeDirFn
	defer func() { setupUserHomeDirFn = origHome }()
	setupUserHomeDirFn = func() (string, error) { return userHome, nil }

	prompt := newSetupPrompter(bytes.NewBufferString("\n"), io.Discard)
	resolved, configPath, err := setupResolveHome(setupOptions{}, prompt)
	if err != nil {
		t.Fatalf("resolve home: %v", err)
	}
	if resolved != filepath.Join(userHome, ".hasp") {
		t.Fatalf("resolved home = %q", resolved)
	}
	if configPath == "" {
		t.Fatal("expected config path")
	}

	if out, err := run("git", "-C", repo, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	projectRoot, err := setupResolveProjectRoot(context.Background(), setupOptions{Repo: repo}, prompt)
	if err != nil {
		t.Fatalf("resolve explicit project root: %v", err)
	}
	if projectRoot == "" {
		t.Fatal("expected canonical project root")
	}
	if _, err := setupResolveProjectRoot(context.Background(), setupOptions{NonInteractive: true}, prompt); err == nil {
		t.Fatal("expected non-interactive project-root error")
	}
}

func TestSetupResolveAgentsAndDetection(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(homeDir, ".cursor"), 0o700); err != nil {
		t.Fatalf("mkdir cursor dir: %v", err)
	}
	origHome := setupUserHomeDirFn
	origLookPath := setupLookPathFn
	defer func() {
		setupUserHomeDirFn = origHome
		setupLookPathFn = origLookPath
	}()
	setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
	setupLookPathFn = func(name string) (string, error) {
		if name == "claude" {
			return "/usr/bin/claude", nil
		}
		return "", os.ErrNotExist
	}

	supported := setupSupportedAgents()
	detected := detectSetupAgents(supported)
	if len(detected) == 0 {
		t.Fatal("expected detected agents")
	}
	if setupAgentBinary("codex-cli") != "codex" || setupAgentBinary("claude-code") != "claude" || setupAgentBinary("cursor") != "cursor" {
		t.Fatal("unexpected agent binary mapping")
	}
	selected, err := selectSetupAgents(supported, []string{"cursor", "claude-code", "cursor"})
	if err != nil {
		t.Fatalf("select agents: %v", err)
	}
	if len(selected) != 2 {
		t.Fatalf("expected deduped selected agents, got %+v", selected)
	}
	if _, err := selectSetupAgents(supported, []string{"missing"}); err == nil {
		t.Fatal("expected unsupported agent error")
	}

	prompt := newSetupPrompter(bytes.NewBufferString("3,2\n"), io.Discard)
	resolved, err := setupResolveAgents(setupOptions{}, prompt)
	if err != nil {
		t.Fatalf("resolve interactive agents: %v", err)
	}
	if len(resolved) != 2 {
		t.Fatalf("expected two resolved agents, got %+v", resolved)
	}
}

func TestSetupResolveBoolOptionsAndPassword(t *testing.T) {
	lockAppSeams(t)
	prompt := newSetupPrompter(bytes.NewBufferString("n\nn\ny\nn\n"), io.Discard)
	opts := setupOptions{}
	agents := []setupAgentSpec{{ID: "claude-code", Format: "json", ConfigPath: func(string) string { return filepath.Join(t.TempDir(), ".claude.json") }}}
	if err := setupResolveBoolOptions(&opts, prompt, agents); err != nil {
		t.Fatalf("resolve bool options: %v", err)
	}
	if opts.AutoProtectRepos.value {
		t.Fatal("expected auto protect repos false")
	}
	if opts.InstallHooks.value {
		t.Fatal("expected install hooks false")
	}
	if !opts.EnableConvenienceUnlock.value {
		t.Fatal("expected convenience unlock true")
	}

	t.Setenv("PW_ENV", "env-password")
	password, exists, err := setupResolvePassword(newSetupPrompter(bytes.NewBuffer(nil), io.Discard), setupOptions{PasswordEnv: "PW_ENV"}, t.TempDir())
	if err != nil || password != "env-password" || exists {
		t.Fatalf("resolve env password = %q exists=%v err=%v", password, exists, err)
	}

	password, _, err = setupResolvePassword(newSetupPrompter(bytes.NewBufferString("stdin-password"), io.Discard), setupOptions{PasswordStdin: true}, t.TempDir())
	if err != nil || password != "stdin-password" {
		t.Fatalf("resolve stdin password = %q err=%v", password, err)
	}

	var retryOut bytes.Buffer
	prompt = newSetupPrompter(bytes.NewBufferString("one\ntwo\ncorrect horse battery staple\ncorrect horse battery staple\n"), &retryOut)
	password, _, err = setupResolvePassword(prompt, setupOptions{}, t.TempDir())
	if err != nil || password != "correct horse battery staple" {
		t.Fatalf("expected retry-after-mismatch password success, got %q err=%v", password, err)
	}
	if !strings.Contains(retryOut.String(), "did not match") {
		t.Fatalf("expected retry message after mismatch, got %q", retryOut.String())
	}
}

func TestPromptHelpersAndPassword(t *testing.T) {
	lockAppSeams(t)
	prompt := newSetupPrompter(bytes.NewBufferString("\n"), io.Discard)
	if value, err := promptString(prompt, "label", "default"); err != nil || value != "default" {
		t.Fatalf("prompt string default = %q err=%v", value, err)
	}
	prompt = newSetupPrompter(bytes.NewBufferString("yes\n"), io.Discard)
	if value, err := promptBool(prompt, "label", false); err != nil || !value {
		t.Fatalf("prompt bool yes = %v err=%v", value, err)
	}
	prompt = newSetupPrompter(bytes.NewBufferString("visible\n"), io.Discard)
	password, err := promptPassword(prompt, "label")
	if err != nil || password != "visible" {
		t.Fatalf("prompt password visible = %q err=%v", password, err)
	}

	tempFile, err := os.CreateTemp(t.TempDir(), "tty-*")
	if err != nil {
		t.Fatalf("create temp tty file: %v", err)
	}
	defer tempFile.Close()
	origCanHide := setupCanHideInputFn
	origStty := setupSttyFn
	defer func() {
		setupCanHideInputFn = origCanHide
		setupSttyFn = origStty
	}()
	setupCanHideInputFn = func(*os.File) bool { return true }
	setupSttyFn = func(_ *os.File, _ ...string) error { return nil }
	prompt = &setupPrompter{reader: bufio.NewReader(bytes.NewBufferString("hidden\n")), out: io.Discard, file: tempFile}
	password, err = promptPassword(prompt, "hidden")
	if err != nil || password != "hidden" {
		t.Fatalf("prompt password hidden = %q err=%v", password, err)
	}
}

func TestSetupImportBindAtomicWriteAndHarness(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	configHome := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	keyring := &memorySetupKeyring{}
	origNewStore := newVaultStoreFn
	defer func() { newVaultStoreFn = origNewStore }()
	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }

	restoreHome, err := setupSetEnv(paths.EnvHome, filepath.Join(homeDir, "vault"))
	if err != nil {
		t.Fatalf("set env: %v", err)
	}
	defer restoreHome()
	restorePassword, err := setupSetEnv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err != nil {
		t.Fatalf("set password env: %v", err)
	}
	defer restorePassword()

	vaultStore, err := newVaultStoreFn()
	if err != nil {
		t.Fatalf("new vault store: %v", err)
	}
	handle, _, err := setupEnsureHandle(context.Background(), vaultStore, "correct horse battery staple", false)
	if err != nil {
		t.Fatalf("ensure handle: %v", err)
	}

	importPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(importPath, []byte("OPENAI_API_KEY=abc123\n"), 0o600); err != nil {
		t.Fatalf("write import path: %v", err)
	}
	imported, err := setupImportAndBind(context.Background(), handle, projectRoot, setupOptions{
		ImportPath:    importPath,
		ImportFormat:  "env",
		BindImports:   true,
		InstallHooks:  setupOptionalBool{set: true, value: false},
		DefaultPolicy: store.PolicySession,
	}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard))
	if err != nil {
		t.Fatalf("import and bind: %v", err)
	}
	if len(imported) != 1 || imported[0].Alias == "" {
		t.Fatalf("expected imported alias, got %+v", imported)
	}
	binding, visible, err := setupFinalizeBinding(context.Background(), handle, projectRoot, setupOptions{
		InstallHooks:  setupOptionalBool{set: true, value: false},
		DefaultPolicy: store.PolicySession,
	})
	if err != nil {
		t.Fatalf("finalize binding: %v", err)
	}
	if len(binding.Aliases) == 0 || len(visible) == 0 {
		t.Fatalf("expected binding visibility, got binding=%+v visible=%+v", binding, visible)
	}

	specs := []setupAgentSpec{{
		ID:     "claude-code",
		Label:  "Claude Code",
		Format: "json",
		ConfigPath: func(string) string {
			return filepath.Join(homeDir, ".claude.json")
		},
	}}
	outcomes, err := setupWriteAgentConfigs(specs, filepath.Join(homeDir, "vault"))
	if err != nil {
		t.Fatalf("write agent configs: %v", err)
	}
	if len(outcomes) != 1 || !outcomes[0].Changed {
		t.Fatalf("expected changed config outcome, got %+v", outcomes)
	}

	samePath := filepath.Join(homeDir, ".same")
	if err := os.WriteFile(samePath, []byte("same"), 0o600); err != nil {
		t.Fatalf("write same file: %v", err)
	}
	backup, changed, err := setupAtomicWrite(samePath, []byte("same"), []byte("same"))
	if err != nil || changed || backup != "" {
		t.Fatalf("expected no-op atomic write, got backup=%q changed=%v err=%v", backup, changed, err)
	}

	verification, err := setupVerifyHarness(context.Background(), specs)
	if err != nil {
		t.Fatalf("verify harness: %v", err)
	}
	mcpReady, _ := verification["mcp"].(map[string]any)
	if ready, _ := mcpReady["ready"].(bool); !ready {
		t.Fatalf("expected ready harness verification, got %+v", verification)
	}

	if !withinPath(filepath.Join(projectRoot, "nested"), projectRoot) || withinPath("/tmp/other", projectRoot) {
		t.Fatal("unexpected withinPath result")
	}
}

func TestSetupAdditionalErrorBranches(t *testing.T) {
	lockAppSeams(t)

	var nilFlags *setupAgentFlags
	if nilFlags.String() != "" {
		t.Fatalf("expected nil setupAgentFlags string to be empty")
	}
	var nilBool *setupOptionalBool
	if nilBool.String() != "" {
		t.Fatalf("expected nil setupOptionalBool string to be empty")
	}

	if _, err := parseSetupOptions([]string{"--master-password-env", "PW", "--master-password-stdin"}); err == nil {
		t.Fatal("expected conflicting password source error")
	}
	if _, err := parseSetupOptions([]string{"--import", "-", "--master-password-stdin"}); err == nil {
		t.Fatal("expected stdin conflict error")
	}
	if _, err := parseSetupOptions([]string{"trailing"}); err == nil {
		t.Fatal("expected trailing arg usage error")
	}

	origHome := setupUserHomeDirFn
	defer func() { setupUserHomeDirFn = origHome }()
	setupUserHomeDirFn = func() (string, error) { return "", errors.New("home fail") }
	fallback := filepath.Join(t.TempDir(), "fallback")
	t.Setenv("HASP_HOME", fallback)
	expectedFallback, err := filepath.EvalSymlinks(filepath.Dir(fallback))
	if err != nil {
		t.Fatalf("eval symlinks fallback dir: %v", err)
	}
	expectedFallback = filepath.Join(expectedFallback, filepath.Base(fallback))
	if got := defaultSetupHome(); got != expectedFallback && got != fallback {
		t.Fatalf("default home fallback = %q", got)
	}

	if err := validateSetupNonInteractive(setupOptions{NonInteractive: true}); err == nil {
		t.Fatal("expected missing non-interactive fields error")
	}

	homeDir := t.TempDir()
	filePath := filepath.Join(homeDir, "file")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file path: %v", err)
	}
	if err := setupValidateHomePath(filePath, t.TempDir()); err == nil {
		t.Fatal("expected non-directory home path error")
	}
	dirPath := filepath.Join(homeDir, "dir")
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		t.Fatalf("mkdir dir path: %v", err)
	}
	if err := setupValidateHomePath(dirPath, t.TempDir()); err == nil {
		t.Fatal("expected permissive home dir error")
	}
	linkPath := filepath.Join(homeDir, "link")
	if err := os.Symlink(dirPath, linkPath); err != nil {
		t.Fatalf("symlink dir path: %v", err)
	}
	if err := setupValidateHomePath(linkPath, t.TempDir()); err == nil {
		t.Fatal("expected symlink home path error")
	}

	if _, _, err := setupResolvePassword(newSetupPrompter(bytes.NewBufferString(""), io.Discard), setupOptions{PasswordEnv: "EMPTY_PW"}, t.TempDir()); err == nil {
		t.Fatal("expected empty env password error")
	}
	if _, _, err := setupResolvePassword(newSetupPrompter(bytes.NewBufferString(""), io.Discard), setupOptions{PasswordStdin: true}, t.TempDir()); err == nil {
		t.Fatal("expected empty stdin password error")
	}
	if _, _, err := setupResolvePassword(newSetupPrompter(bytes.NewBufferString(""), io.Discard), setupOptions{NonInteractive: true}, t.TempDir()); err == nil {
		t.Fatal("expected missing non-interactive password error")
	}
	prompt := newSetupPrompter(bytes.NewBufferString("\n"), io.Discard)
	vaultHome := filepath.Join(t.TempDir(), "vault")
	if err := os.MkdirAll(vaultHome, 0o700); err != nil {
		t.Fatalf("mkdir vault home: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vaultHome, "vault.json.enc"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write fake vault: %v", err)
	}
	if _, _, err := setupResolvePassword(prompt, setupOptions{}, vaultHome); err == nil {
		t.Fatal("expected missing existing-vault password error")
	}

	keyring := &memorySetupKeyring{}
	origNewStore := newVaultStoreFn
	defer func() { newVaultStoreFn = origNewStore }()
	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }
	storeHandle, err := newVaultStoreFn()
	if err != nil {
		t.Fatalf("new vault store: %v", err)
	}
	if err := storeHandle.Init(context.Background(), "pw"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	if _, _, err := setupEnsureHandle(context.Background(), storeHandle, "wrong", true); err == nil {
		t.Fatal("expected wrong password on existing vault")
	}

	attempts := 0
	var promptOut bytes.Buffer
	prompt = newSetupPrompter(bytes.NewBufferString("correct-password\n"), &promptOut)
	origOpenStore := openStoreWithPasswordFn
	defer func() { openStoreWithPasswordFn = origOpenStore }()
	openStoreWithPasswordFn = func(context.Context, *store.Store, string) (*store.Handle, error) {
		attempts++
		if attempts == 1 {
			return nil, store.ErrInvalidPassword
		}
		return &store.Handle{}, nil
	}
	handle, state, password, err := setupOpenHandleWithRetry(context.Background(), prompt, storeHandle, "wrong", true, false)
	if err != nil || handle == nil || state != "existing" || password != "correct-password" {
		t.Fatalf("expected retry success, got handle=%v state=%q password=%q err=%v", handle != nil, state, password, err)
	}
	if !strings.Contains(promptOut.String(), "invalid master password") {
		t.Fatalf("expected invalid password retry message, got %q", promptOut.String())
	}

	prompt = newSetupPrompter(bytes.NewBufferString(""), errWriter{err: errors.New("retry write fail")})
	openStoreWithPasswordFn = func(context.Context, *store.Store, string) (*store.Handle, error) {
		return nil, store.ErrInvalidPassword
	}
	if _, _, _, err := setupOpenHandleWithRetry(context.Background(), prompt, storeHandle, "wrong", true, false); err == nil || !strings.Contains(err.Error(), "retry write fail") {
		t.Fatalf("expected retry write failure, got %v", err)
	}

	prompt = newSetupPrompter(setupErrReader{}, io.Discard)
	if _, _, _, err := setupOpenHandleWithRetry(context.Background(), prompt, storeHandle, "wrong", true, false); err == nil {
		t.Fatal("expected retry prompt read failure")
	}

	prompt = newSetupPrompter(bytes.NewBufferString("\n"), io.Discard)
	if _, _, _, err := setupOpenHandleWithRetry(context.Background(), prompt, storeHandle, "wrong", true, false); err == nil || !strings.Contains(err.Error(), "master password is required") {
		t.Fatalf("expected empty retry password failure, got %v", err)
	}

	specs := []setupAgentSpec{{
		ID: "bad", Label: "Bad", Format: "yaml", ConfigPath: func(string) string {
			return filepath.Join(t.TempDir(), "bad.cfg")
		},
	}}
	if _, err := setupWriteAgentConfigs(specs, ""); err == nil {
		t.Fatal("expected unsupported setup config format error")
	}

	symlinkTarget := filepath.Join(t.TempDir(), "real.json")
	if err := os.WriteFile(symlinkTarget, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	symlinkPath := filepath.Join(t.TempDir(), "linked.json")
	if err := os.Symlink(symlinkTarget, symlinkPath); err != nil {
		t.Fatalf("symlink config path: %v", err)
	}
	specs = []setupAgentSpec{{
		ID: "claude-code", Label: "Claude Code", Format: "json", ConfigPath: func(string) string { return symlinkPath },
	}}
	if _, err := setupWriteAgentConfigs(specs, ""); err == nil {
		t.Fatal("expected symlink config rejection")
	}

	origCreateTemp := setupCreateTempFn
	origRename := setupRenameFn
	origMkdir := setupMkdirAllFn
	origWrite := setupWriteFileFn
	defer func() {
		setupCreateTempFn = origCreateTemp
		setupRenameFn = origRename
		setupMkdirAllFn = origMkdir
		setupWriteFileFn = origWrite
	}()
	setupMkdirAllFn = func(string, os.FileMode) error { return errors.New("mkdir fail") }
	if _, _, err := setupAtomicWrite(filepath.Join(t.TempDir(), "x"), nil, []byte("x")); err == nil {
		t.Fatal("expected mkdir failure")
	}
	setupMkdirAllFn = os.MkdirAll
	setupCreateTempFn = func(string, string) (*os.File, error) { return nil, errors.New("temp fail") }
	if _, _, err := setupAtomicWrite(filepath.Join(t.TempDir(), "x"), []byte("old"), []byte("new")); err == nil {
		t.Fatal("expected temp file creation failure")
	}
	setupCreateTempFn = os.CreateTemp
	setupRenameFn = func(string, string) error { return errors.New("rename fail") }
	if _, _, err := setupAtomicWrite(filepath.Join(t.TempDir(), "y"), []byte("old"), []byte("new")); err == nil {
		t.Fatal("expected rename failure")
	}
	setupRenameFn = os.Rename
	setupWriteFileFn = func(string, []byte, os.FileMode) error { return errors.New("backup fail") }
	if _, _, err := setupAtomicWrite(filepath.Join(t.TempDir(), "z"), []byte("old"), []byte("new")); err == nil {
		t.Fatal("expected backup write failure")
	}

	if _, err := upsertJSONMCPServerConfig([]byte(`{"mcpServers":"bad"}`), "", "/bin/hasp"); err == nil {
		t.Fatal("expected invalid existing mcpServers object error")
	}
}

func TestSetupSetEnvAndInteractiveSetup(t *testing.T) {
	lockAppSeams(t)

	restore, err := setupSetEnv("HASP_SETUP_TEMP", "value")
	if err != nil {
		t.Fatalf("setupSetEnv: %v", err)
	}
	if os.Getenv("HASP_SETUP_TEMP") != "value" {
		t.Fatal("expected temporary env value")
	}
	restore()
	if os.Getenv("HASP_SETUP_TEMP") != "" {
		t.Fatal("expected env restore cleanup")
	}

	userHome := t.TempDir()
	haspHome := filepath.Join(userHome, ".hasp")
	repo := t.TempDir()
	if out, err := run("git", "-C", repo, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	keyring := &memorySetupKeyring{}
	origNewStore := newVaultStoreFn
	origHome := setupUserHomeDirFn
	origLookPath := setupLookPathFn
	defer func() {
		newVaultStoreFn = origNewStore
		setupUserHomeDirFn = origHome
		setupLookPathFn = origLookPath
	}()
	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }
	setupUserHomeDirFn = func() (string, error) { return userHome, nil }
	setupLookPathFn = func(name string) (string, error) {
		if name == "codex" {
			return "/usr/bin/codex", nil
		}
		return "", os.ErrNotExist
	}

	t.Setenv("HOME", userHome)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(userHome, ".config"))

	input := strings.Join([]string{
		"",
		"",
		"n",
		"n",
		"n",
		"n",
		"y",
		"correct horse battery staple",
		"correct horse battery staple",
	}, "\n") + "\n"
	var stdout bytes.Buffer
	if err := setupCommand(context.Background(), nil, bytes.NewBufferString(input), &stdout, io.Discard); err != nil {
		t.Fatalf("interactive setup: %v", err)
	}

	text := stdout.String()
	if !strings.Contains(text, "Setup complete") {
		t.Fatalf("expected human setup summary, got %q", text)
	}
	if !strings.Contains(text, haspHome) || !strings.Contains(text, "Automatic repo adoption") {
		t.Fatalf("expected summary to mention hasp home and machine defaults, got %q", text)
	}
}
