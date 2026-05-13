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
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestSetupResidualCoverageBranches(t *testing.T) {
	t.Run("runSetup convenience error branch", func(t *testing.T) {
		lockAppSeams(t)
		homeDir := t.TempDir()
		projectRoot := t.TempDir()
		t.Setenv("HOME", homeDir)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))
		t.Setenv("SETUP_RESIDUAL_PW", "correct horse battery staple")

		origHome := setupUserHomeDirFn
		origNewStore := newVaultStoreFn
		origEnable := setupEnableConvenienceUnlockFn
		origVerify := setupVerifyConvenienceUnlockFn
		origCanon := setupCanonicalProjectRoot
		defer func() {
			setupUserHomeDirFn = origHome
			newVaultStoreFn = origNewStore
			setupEnableConvenienceUnlockFn = origEnable
			setupVerifyConvenienceUnlockFn = origVerify
			setupCanonicalProjectRoot = origCanon
		}()

		setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
		setupCanonicalProjectRoot = func(_ context.Context, value string) (string, error) { return value, nil }
		newVaultStoreFn = func() (*store.Store, error) { return store.New(&memorySetupKeyring{}) }
		setupEnableConvenienceUnlockFn = func(context.Context, *store.Handle) error { return errors.New("unlock fail") }

		_, err := runSetup(context.Background(), setupOptions{
			NonInteractive:          true,
			HaspHome:                filepath.Join(t.TempDir(), "hasp-home"),
			Repo:                    projectRoot,
			Agents:                  setupAgentFlags{"codex-cli"},
			PasswordEnv:             "SETUP_RESIDUAL_PW",
			InstallHooks:            setupOptionalBool{set: true, value: false},
			EnableConvenienceUnlock: setupOptionalBool{set: true, value: true},
			OverwriteExistingConfig: setupOptionalBool{set: true, value: true},
			DefaultPolicy:           store.PolicySession,
		}, bytes.NewBuffer(nil), io.Discard)
		if err == nil || !strings.Contains(err.Error(), "unlock fail") {
			t.Fatalf("expected convenience unlock failure, got %v", err)
		}
	})

	t.Run("runSetup convenience verify unavailable branch", func(t *testing.T) {
		lockAppSeams(t)
		homeDir := t.TempDir()
		projectRoot := t.TempDir()
		t.Setenv("HOME", homeDir)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))
		t.Setenv("SETUP_RESIDUAL_PW", "correct horse battery staple")

		origHome := setupUserHomeDirFn
		origNewStore := newVaultStoreFn
		origEnable := setupEnableConvenienceUnlockFn
		origVerify := setupVerifyConvenienceUnlockFn
		origCanon := setupCanonicalProjectRoot
		origRetries := setupConvenienceVerifyRetries
		origDelay := setupConvenienceRetryDelay
		origSleep := setupSleepFn
		defer func() {
			setupUserHomeDirFn = origHome
			newVaultStoreFn = origNewStore
			setupEnableConvenienceUnlockFn = origEnable
			setupVerifyConvenienceUnlockFn = origVerify
			setupCanonicalProjectRoot = origCanon
			setupConvenienceVerifyRetries = origRetries
			setupConvenienceRetryDelay = origDelay
			setupSleepFn = origSleep
		}()

		setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
		setupCanonicalProjectRoot = func(_ context.Context, value string) (string, error) { return value, nil }
		newVaultStoreFn = func() (*store.Store, error) { return store.New(&memorySetupKeyring{}) }
		setupEnableConvenienceUnlockFn = func(context.Context, *store.Handle) error { return nil }
		verifyCalls := 0
		setupConvenienceVerifyRetries = 2
		setupConvenienceRetryDelay = 0
		setupSleepFn = func(time.Duration) {}
		setupVerifyConvenienceUnlockFn = func(context.Context, *store.Store) error {
			verifyCalls++
			return store.ErrKeyringUnavailable
		}

		summary, err := runSetup(context.Background(), setupOptions{
			NonInteractive:          true,
			HaspHome:                filepath.Join(t.TempDir(), "hasp-home"),
			Repo:                    projectRoot,
			Agents:                  setupAgentFlags{"codex-cli"},
			PasswordEnv:             "SETUP_RESIDUAL_PW",
			InstallHooks:            setupOptionalBool{set: true, value: false},
			EnableConvenienceUnlock: setupOptionalBool{set: true, value: true},
			OverwriteExistingConfig: setupOptionalBool{set: true, value: true},
			DefaultPolicy:           store.PolicySession,
		}, bytes.NewBuffer(nil), io.Discard)
		if err != nil {
			t.Fatalf("run setup with unavailable verify: %v", err)
		}
		if summary.ConvenienceUnlock != "unavailable" {
			t.Fatalf("expected unavailable convenience unlock after failed verify, got %+v", summary)
		}
		if verifyCalls != 2 {
			t.Fatalf("expected convenience verify retry count, got %d", verifyCalls)
		}
		if !strings.Contains(strings.Join(summary.Notes, "\n"), "convenience unlock detail: macOS keychain access did not complete during setup") {
			t.Fatalf("expected convenience detail note, got %+v", summary.Notes)
		}
	})

	t.Run("runSetup convenience enable timeout becomes unavailable", func(t *testing.T) {
		lockAppSeams(t)
		homeDir := t.TempDir()
		projectRoot := t.TempDir()
		t.Setenv("HOME", homeDir)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))
		t.Setenv("SETUP_RESIDUAL_PW", "correct horse battery staple")

		origHome := setupUserHomeDirFn
		origNewStore := newVaultStoreFn
		origEnable := setupEnableConvenienceUnlockFn
		origVerify := setupVerifyConvenienceUnlockFn
		origCanon := setupCanonicalProjectRoot
		origTimeout := setupConvenienceUnlockTimeout
		defer func() {
			setupUserHomeDirFn = origHome
			newVaultStoreFn = origNewStore
			setupEnableConvenienceUnlockFn = origEnable
			setupVerifyConvenienceUnlockFn = origVerify
			setupCanonicalProjectRoot = origCanon
			setupConvenienceUnlockTimeout = origTimeout
		}()

		setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
		setupCanonicalProjectRoot = func(_ context.Context, value string) (string, error) { return value, nil }
		newVaultStoreFn = func() (*store.Store, error) { return store.New(&memorySetupKeyring{}) }
		setupConvenienceUnlockTimeout = time.Millisecond
		setupEnableConvenienceUnlockFn = func(ctx context.Context, _ *store.Handle) error {
			<-ctx.Done()
			return ctx.Err()
		}
		setupVerifyConvenienceUnlockFn = func(context.Context, *store.Store) error {
			t.Fatal("verify should not run after enable timeout")
			return nil
		}

		summary, err := runSetup(context.Background(), setupOptions{
			NonInteractive:          true,
			HaspHome:                filepath.Join(t.TempDir(), "hasp-home"),
			Repo:                    projectRoot,
			Agents:                  setupAgentFlags{"codex-cli"},
			PasswordEnv:             "SETUP_RESIDUAL_PW",
			InstallHooks:            setupOptionalBool{set: true, value: false},
			EnableConvenienceUnlock: setupOptionalBool{set: true, value: true},
			OverwriteExistingConfig: setupOptionalBool{set: true, value: true},
			DefaultPolicy:           store.PolicySession,
		}, bytes.NewBuffer(nil), io.Discard)
		if err != nil {
			t.Fatalf("run setup with timed-out convenience enable: %v", err)
		}
		if summary.ConvenienceUnlock != "unavailable" {
			t.Fatalf("expected unavailable convenience unlock after enable timeout, got %+v", summary)
		}
	})

	t.Run("runSetup convenience verify generic failure branch", func(t *testing.T) {
		lockAppSeams(t)
		homeDir := t.TempDir()
		projectRoot := t.TempDir()
		t.Setenv("HOME", homeDir)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))
		t.Setenv("SETUP_RESIDUAL_PW", "correct horse battery staple")

		origHome := setupUserHomeDirFn
		origNewStore := newVaultStoreFn
		origEnable := setupEnableConvenienceUnlockFn
		origVerify := setupVerifyConvenienceUnlockFn
		origCanon := setupCanonicalProjectRoot
		defer func() {
			setupUserHomeDirFn = origHome
			newVaultStoreFn = origNewStore
			setupEnableConvenienceUnlockFn = origEnable
			setupVerifyConvenienceUnlockFn = origVerify
			setupCanonicalProjectRoot = origCanon
		}()

		setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
		setupCanonicalProjectRoot = func(_ context.Context, value string) (string, error) { return value, nil }
		newVaultStoreFn = func() (*store.Store, error) { return store.New(&memorySetupKeyring{}) }
		setupEnableConvenienceUnlockFn = func(context.Context, *store.Handle) error { return nil }
		setupVerifyConvenienceUnlockFn = func(context.Context, *store.Store) error { return errors.New("verify fail") }

		_, err := runSetup(context.Background(), setupOptions{
			NonInteractive:          true,
			HaspHome:                filepath.Join(t.TempDir(), "hasp-home"),
			Repo:                    projectRoot,
			Agents:                  setupAgentFlags{"codex-cli"},
			PasswordEnv:             "SETUP_RESIDUAL_PW",
			InstallHooks:            setupOptionalBool{set: true, value: false},
			EnableConvenienceUnlock: setupOptionalBool{set: true, value: true},
			OverwriteExistingConfig: setupOptionalBool{set: true, value: true},
			DefaultPolicy:           store.PolicySession,
		}, bytes.NewBuffer(nil), io.Discard)
		if err == nil || !strings.Contains(err.Error(), "verify fail") {
			t.Fatalf("expected convenience verify failure, got %v", err)
		}
	})

	t.Run("runSetup intro and selected-agent write errors", func(t *testing.T) {
		lockAppSeams(t)
		homeDir := t.TempDir()
		projectRoot := t.TempDir()
		t.Setenv("HOME", homeDir)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))
		t.Setenv("SETUP_RESIDUAL_PW", "correct horse battery staple")

		origHome := setupUserHomeDirFn
		origCanon := setupCanonicalProjectRoot
		origNewStore := newVaultStoreFn
		origWriteIntro := setupWriteIntroFn
		origWriteSelected := setupWriteSelectedAgentsFn
		origWriteConfirmation := setupWriteConfirmationFn
		defer func() {
			setupUserHomeDirFn = origHome
			setupCanonicalProjectRoot = origCanon
			newVaultStoreFn = origNewStore
			setupWriteIntroFn = origWriteIntro
			setupWriteSelectedAgentsFn = origWriteSelected
			setupWriteConfirmationFn = origWriteConfirmation
		}()
		setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
		setupCanonicalProjectRoot = func(_ context.Context, value string) (string, error) { return value, nil }
		newVaultStoreFn = func() (*store.Store, error) { return store.New(&memorySetupKeyring{}) }

		opts := setupOptions{
			HaspHome:                filepath.Join(t.TempDir(), "hasp-home"),
			Repo:                    projectRoot,
			Agents:                  setupAgentFlags{"codex-cli"},
			PasswordEnv:             "SETUP_RESIDUAL_PW",
			InstallHooks:            setupOptionalBool{set: true, value: false},
			EnableConvenienceUnlock: setupOptionalBool{set: true, value: false},
			OverwriteExistingConfig: setupOptionalBool{set: true, value: true},
		}
		setupWriteIntroFn = func(io.Writer) error { return errors.New("intro fail") }
		if _, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "intro fail") {
			t.Fatalf("expected intro failure, got %v", err)
		}
		setupWriteIntroFn = origWriteIntro
		setupWriteSelectedAgentsFn = func(io.Writer, []setupAgentSpec) error { return errors.New("selected fail") }
		if _, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "selected fail") {
			t.Fatalf("expected selected-agent write failure, got %v", err)
		}
		setupWriteSelectedAgentsFn = origWriteSelected
		setupWriteConfirmationFn = func(io.Writer, setupPlanPreview) error { return errors.New("confirm fail") }
		if _, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "confirm fail") {
			t.Fatalf("expected confirmation write failure, got %v", err)
		}
	})

	t.Run("setupResolveHome seam errors", func(t *testing.T) {
		lockAppSeams(t)
		origConfigPath := setupConfigPathFn
		origLoad := setupLoadConfigFn
		origAbs := setupAbsFn
		origHome := setupUserHomeDirFn
		defer func() {
			setupConfigPathFn = origConfigPath
			setupLoadConfigFn = origLoad
			setupAbsFn = origAbs
			setupUserHomeDirFn = origHome
		}()

		setupConfigPathFn = func() (string, error) { return "", errors.New("config path fail") }
		if _, _, err := setupResolveHome(setupOptions{}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard)); err == nil || !strings.Contains(err.Error(), "config path fail") {
			t.Fatalf("expected config path failure, got %v", err)
		}

		setupConfigPathFn = origConfigPath
		setupUserHomeDirFn = func() (string, error) { return "", errors.New("home fail") }
		if _, _, err := setupResolveHome(setupOptions{HaspHome: "~/vault"}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard)); err == nil || !strings.Contains(err.Error(), "home fail") {
			t.Fatalf("expected expandHome failure, got %v", err)
		}

		setupUserHomeDirFn = func() (string, error) { return "/Users/tester", nil }
		setupLoadConfigFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, errors.New("load fail") }
		if _, _, err := setupResolveHome(setupOptions{}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard)); err == nil || !strings.Contains(err.Error(), "load fail") {
			t.Fatalf("expected load config failure, got %v", err)
		}

		setupLoadConfigFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, nil }
		if _, _, err := setupResolveHome(setupOptions{}, newSetupPrompter(setupErrReader{}, io.Discard)); err == nil {
			t.Fatal("expected prompt failure")
		}

		setupAbsFn = func(string) (string, error) { return "", errors.New("abs fail") }
		if _, _, err := setupResolveHome(setupOptions{}, newSetupPrompter(bytes.NewBufferString("custom\n"), io.Discard)); err == nil || !strings.Contains(err.Error(), "abs fail") {
			t.Fatalf("expected abs failure, got %v", err)
		}
	})

	t.Run("project root and agent resolution residual branches", func(t *testing.T) {
		lockAppSeams(t)
		origCanon := setupCanonicalProjectRoot
		origLookPath := setupLookPathFn
		origHome := setupUserHomeDirFn
		defer func() {
			setupCanonicalProjectRoot = origCanon
			setupLookPathFn = origLookPath
			setupUserHomeDirFn = origHome
		}()

		setupCanonicalProjectRoot = func(_ context.Context, value string) (string, error) {
			if value == "." {
				return "", errors.New("canon default fail")
			}
			return value, nil
		}
		if _, err := setupResolveProjectRoot(context.Background(), setupOptions{}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard)); err == nil || !strings.Contains(err.Error(), "canon default fail") {
			t.Fatalf("expected default canonical root failure, got %v", err)
		}

		setupCanonicalProjectRoot = func(_ context.Context, value string) (string, error) { return value, nil }
		if _, err := setupResolveProjectRoot(context.Background(), setupOptions{}, newSetupPrompter(setupErrReader{}, io.Discard)); err == nil {
			t.Fatal("expected project root prompt failure")
		}
		if _, err := setupResolveProjectRoot(context.Background(), setupOptions{}, newSetupPrompter(bytes.NewBuffer(nil), errWriter{err: errors.New("stage fail")})); err == nil {
			t.Fatal("expected project root stage writer failure")
		}

		setupLookPathFn = func(string) (string, error) { return "", os.ErrNotExist }
		setupUserHomeDirFn = func() (string, error) { return t.TempDir(), nil }
		if resolved, err := setupResolveAgents(setupOptions{NonInteractive: true}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard)); err != nil || len(resolved) != 0 {
			t.Fatalf("expected non-interactive no-agent success, got %+v err=%v", resolved, err)
		}
		if _, err := setupResolveAgents(setupOptions{}, newSetupPrompter(setupErrReader{}, io.Discard)); err == nil {
			t.Fatal("expected interactive agent prompt failure")
		}
		if _, err := setupResolveAgents(setupOptions{}, newSetupPrompter(bytes.NewBufferString("9\n"), io.Discard)); err == nil {
			t.Fatal("expected interactive invalid menu selection failure")
		}
		if _, err := setupResolveAgents(setupOptions{}, newSetupPrompter(bytes.NewBuffer(nil), errWriter{err: errors.New("stage fail")})); err == nil {
			t.Fatal("expected agent stage writer failure")
		}
	})

	t.Run("bool options and validate home residual branches", func(t *testing.T) {
		lockAppSeams(t)
		configPath := filepath.Join(t.TempDir(), ".claude.json")
		if err := os.WriteFile(configPath, []byte(`{}`), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		opts := setupOptions{
			InstallHooks:            setupOptionalBool{set: true, value: false},
			EnableConvenienceUnlock: setupOptionalBool{set: true, value: false},
			ImportPath:              "already-set",
			BindImports:             true,
		}
		agents := []setupAgentSpec{{ID: "claude-code", ConfigPath: func(string) string { return configPath }}}
		if err := setupResolveBoolOptions(&opts, newSetupPrompter(setupErrReader{}, io.Discard), agents); err == nil {
			t.Fatal("expected overwrite prompt failure")
		}
		opts = setupOptions{
			AutoProtectRepos:        setupOptionalBool{set: true, value: true},
			InstallHooks:            setupOptionalBool{set: true, value: false},
			EnableConvenienceUnlock: setupOptionalBool{set: true, value: false},
		}
		if err := setupResolveBoolOptions(&opts, newSetupPrompter(bytes.NewBuffer(nil), errWriter{err: errors.New("stage fail")}), nil); err == nil {
			t.Fatal("expected optional import stage writer failure")
		}
		opts = setupOptions{
			AutoProtectRepos:        setupOptionalBool{set: true, value: true},
			InstallHooks:            setupOptionalBool{set: true, value: false},
			EnableConvenienceUnlock: setupOptionalBool{set: true, value: false},
		}
		if err := setupResolveBoolOptions(&opts, newSetupPrompter(io.MultiReader(strings.NewReader("y\n"), setupErrReader{}), io.Discard), nil); err == nil {
			t.Fatal("expected import path prompt failure")
		}
		opts = setupOptions{
			Repo:                    t.TempDir(),
			AutoProtectRepos:        setupOptionalBool{set: true, value: true},
			InstallHooks:            setupOptionalBool{set: true, value: false},
			EnableConvenienceUnlock: setupOptionalBool{set: true, value: false},
			ImportPath:              "/tmp/.env",
		}
		if err := setupResolveBoolOptions(&opts, newSetupPrompter(setupErrReader{}, io.Discard), nil); err == nil {
			t.Fatal("expected bind-import prompt failure")
		}

		parentFile := filepath.Join(t.TempDir(), "parent")
		if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
			t.Fatalf("write parent file: %v", err)
		}
		if err := setupValidateHomePath(filepath.Join(parentFile, "child"), t.TempDir()); err == nil {
			t.Fatal("expected lstat error")
		}
	})

	t.Run("password and handle residual branches", func(t *testing.T) {
		lockAppSeams(t)
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, "vault.json.enc"), []byte("x"), 0o600); err != nil {
			t.Fatalf("write fake vault: %v", err)
		}
		if _, _, err := setupResolvePassword(newSetupPrompter(setupErrReader{}, io.Discard), setupOptions{}, home); err == nil {
			t.Fatal("expected existing-vault prompt error")
		}
		if _, _, err := setupResolvePassword(newSetupPrompter(setupErrReader{}, io.Discard), setupOptions{}, t.TempDir()); err == nil {
			t.Fatal("expected first prompt error")
		}
		secondReader := io.MultiReader(strings.NewReader("first\n"), errReader{err: errors.New("second fail")})
		if _, _, err := setupResolvePassword(newSetupPrompter(secondReader, io.Discard), setupOptions{}, t.TempDir()); err == nil || !strings.Contains(err.Error(), "second fail") {
			t.Fatalf("expected second prompt error, got %v", err)
		}
		prompt := newSetupPrompter(bytes.NewBufferString("one\ntwo\ncorrect\ncorrect\n"), errWriter{err: errors.New("write fail")})
		if _, _, err := setupResolvePassword(prompt, setupOptions{}, t.TempDir()); err == nil {
			t.Fatal("expected retry message write failure")
		}

		t.Setenv("HASP_HOME", t.TempDir())
		vaultStore, err := store.New(&memorySetupKeyring{})
		if err != nil {
			t.Fatalf("new store: %v", err)
		}
		if _, _, err := setupEnsureHandle(context.Background(), vaultStore, "", false, true); err == nil || !strings.Contains(err.Error(), "master password is required") {
			t.Fatalf("expected init validation failure, got %v", err)
		}
	})

	t.Run("import, write config, and prompt password residual branches", func(t *testing.T) {
		lockAppSeams(t)
		t.Setenv("HASP_HOME", t.TempDir())
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
		if _, err := setupImportAndBind(context.Background(), handle, t.TempDir(), setupOptions{
			ImportPath:   filepath.Join(t.TempDir(), "missing.env"),
			ImportFormat: "env",
		}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard)); err == nil {
			t.Fatal("expected prepareImport failure")
		}
		if _, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{}); err != nil {
			t.Fatalf("upsert item: %v", err)
		}
		imported, err := setupImportAndBind(context.Background(), handle, t.TempDir(), setupOptions{
			BindItems: []string{"api_token"},
		}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard))
		if err != nil || len(imported) != 1 || imported[0].Alias == "" {
			t.Fatalf("expected successful bind item import, got %+v err=%v", imported, err)
		}

		parentFile := filepath.Join(t.TempDir(), "parent")
		if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
			t.Fatalf("write parent file: %v", err)
		}
		if _, err := setupWriteAgentConfigs([]setupAgentSpec{{
			ID:     "cursor",
			Format: "json",
			ConfigPath: func(string) string {
				return filepath.Join(parentFile, "child.json")
			},
		}}, ""); err == nil {
			t.Fatal("expected non-ENOENT lstat error")
		}

		tempFile, err := os.CreateTemp(t.TempDir(), "tty-*")
		if err != nil {
			t.Fatalf("create tty file: %v", err)
		}
		defer tempFile.Close()
		origCanHide := setupCanHideInputFn
		origStty := setupSttyFn
		defer func() {
			setupCanHideInputFn = origCanHide
			setupSttyFn = origStty
		}()
		setupCanHideInputFn = func(*os.File) bool { return true }
		setupSttyFn = func(*os.File, ...string) error { return errors.New("stty fail") }
		prompt := &setupPrompter{reader: bufio.NewReader(bytes.NewBufferString("visible\n")), out: &setupNthWriteErrWriter{allow: 0, err: errors.New("write fail")}, file: tempFile}
		if _, err := promptPassword(prompt, "pw"); err == nil || !strings.Contains(err.Error(), "write fail") {
			t.Fatalf("expected prompt password write failure, got %v", err)
		}
		prompt = &setupPrompter{reader: bufio.NewReader(bytes.NewBufferString("visible\n")), out: io.Discard, file: tempFile}
		if password, err := promptPassword(prompt, "pw"); err != nil || password != "visible" {
			t.Fatalf("expected stty fallback visible password, got %q err=%v", password, err)
		}
	})

	t.Run("setupConfirmPlan cancel path", func(t *testing.T) {
		lockAppSeams(t)
		prompt := newSetupPrompter(bytes.NewBufferString("n\n"), io.Discard)
		if err := setupConfirmPlan(prompt, setupPlanPreview{HaspHome: "/tmp/.hasp", ProjectRoot: "/tmp/repo"}); err == nil || !strings.Contains(err.Error(), "cancelled") {
			t.Fatalf("expected cancelled confirmation, got %v", err)
		}
		prompt = newSetupPrompter(setupErrReader{}, io.Discard)
		if err := setupConfirmPlan(prompt, setupPlanPreview{HaspHome: "/tmp/.hasp", ProjectRoot: "/tmp/repo"}); err == nil {
			t.Fatal("expected confirmation prompt failure")
		}
	})
}

func TestSetupFinalCoverageBranches(t *testing.T) {
	lockAppSeams(t)

	t.Run("runSetup propagates first-run prompt failure", func(t *testing.T) {
		homeDir := t.TempDir()
		projectRoot := t.TempDir()
		importPath := filepath.Join(t.TempDir(), ".env")
		if err := os.WriteFile(importPath, []byte("OPENAI_API_KEY=abc123\n"), 0o600); err != nil {
			t.Fatalf("write import file: %v", err)
		}
		t.Setenv("HOME", homeDir)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))
		t.Setenv("SETUP_FINAL_PW", "correct horse battery staple")

		origHome := setupUserHomeDirFn
		origCanon := setupCanonicalProjectRoot
		origNewStore := newVaultStoreFn
		defer func() {
			setupUserHomeDirFn = origHome
			setupCanonicalProjectRoot = origCanon
			newVaultStoreFn = origNewStore
		}()
		setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
		setupCanonicalProjectRoot = func(_ context.Context, value string) (string, error) { return value, nil }
		newVaultStoreFn = func() (*store.Store, error) { return store.New(&memorySetupKeyring{}) }

		_, err := runSetup(context.Background(), setupOptions{
			HaspHome:                filepath.Join(t.TempDir(), "hasp-home"),
			Repo:                    projectRoot,
			Agents:                  setupAgentFlags{"codex-cli"},
			PasswordEnv:             "SETUP_FINAL_PW",
			ImportPath:              importPath,
			BindImports:             true,
			AutoProtectRepos:        setupOptionalBool{set: true, value: true},
			InstallHooks:            setupOptionalBool{set: true, value: false},
			EnableConvenienceUnlock: setupOptionalBool{set: true, value: false},
			OverwriteExistingConfig: setupOptionalBool{set: true, value: true},
		}, bytes.NewBufferString("n\ny\nn\ny\nn\nmyapp\ntrue\ny\nMISSING\nenv\nOPENAI_API_KEY\nn\nn\n"), io.Discard)
		if err == nil || !strings.Contains(err.Error(), "item not found") {
			t.Fatalf("expected first-run connect-app failure, got %v", err)
		}
	})

	t.Run("setupPromptExistingVaultPassword residual branches", func(t *testing.T) {
		origCanHide := setupCanHideInputFn
		origStty := setupSttyFn
		defer func() {
			setupCanHideInputFn = origCanHide
			setupSttyFn = origStty
		}()

		setupCanHideInputFn = func(*os.File) bool { return false }
		if _, err := setupPromptExistingVaultPassword(newSetupPrompter(bytes.NewBufferString("\n"), io.Discard)); err == nil || !strings.Contains(err.Error(), "master password is required") {
			t.Fatalf("expected visible blank password error, got %v", err)
		}

		tempFile, err := os.CreateTemp(t.TempDir(), "existing-vault-password")
		if err != nil {
			t.Fatalf("create temp file: %v", err)
		}
		defer tempFile.Close()
		setupCanHideInputFn = func(*os.File) bool { return true }
		setupSttyFn = func(*os.File, ...string) error { return nil }
		prompt := &setupPrompter{
			reader: bufio.NewReader(bytes.NewBufferString("\n")),
			out:    &setupNthWriteErrWriter{allow: 2, err: errors.New("retry write fail")},
			file:   tempFile,
		}
		if _, err := setupPromptExistingVaultPassword(prompt); err == nil || !strings.Contains(err.Error(), "retry write fail") {
			t.Fatalf("expected retry write failure, got %v", err)
		}
	})

	t.Run("renderSetupSummary and confirmation residual branches", func(t *testing.T) {
		summary := setupSummary{
			HaspHome:          "/tmp/.hasp",
			ConfigPath:        "/tmp/hasp-cli.json",
			InitState:         "created",
			ProjectRoot:       "/tmp/repo",
			ConvenienceUnlock: "enabled",
			AddedSecrets: []secretMutationView{{
				Name:      "API_TOKEN",
				Outcome:   "updated",
				Reference: "secret_01",
			}},
			Apps: []setupAppOutcome{{
				Name:        "repoapp",
				ProjectRoot: "/tmp/repo",
				PathUpdate:  appPathUpdateResult{Changed: true},
			}},
		}

		var out bytes.Buffer
		if err := renderSetupSummary(&out, summary); err != nil {
			t.Fatalf("render setup summary: %v", err)
		}
		text := out.String()
		if !strings.Contains(text, "(secret_01)") {
			t.Fatalf("expected secret reference suffix, got %q", text)
		}
		if !strings.Contains(text, "(/tmp/repo)") || !strings.Contains(text, "(PATH updated)") {
			t.Fatalf("expected app suffixes, got %q", text)
		}

		countWriter := &setupCountWriter{}
		if err := renderSetupSummary(countWriter, summary); err != nil {
			t.Fatalf("count render setup summary: %v", err)
		}
		for failAt := 1; failAt <= countWriter.writes; failAt++ {
			writer := &setupNthWriteErrWriter{allow: failAt - 1, err: errors.New("write fail")}
			if err := renderSetupSummary(writer, summary); err == nil {
				t.Fatalf("expected render setup summary failure at write %d", failAt)
			}
		}

		plan := setupPlanPreview{
			HaspHome:                "/tmp/.hasp",
			ProjectRoot:             "/tmp/repo",
			ConfigExists:            true,
			AutoProtectRepos:        true,
			InstallHooks:            true,
			EnableConvenienceUnlock: true,
		}
		countWriter = &setupCountWriter{}
		if err := setupWriteConfirmation(countWriter, plan); err != nil {
			t.Fatalf("count write confirmation: %v", err)
		}
		for failAt := 1; failAt <= countWriter.writes; failAt++ {
			writer := &setupNthWriteErrWriter{allow: failAt - 1, err: errors.New("write fail")}
			if err := setupWriteConfirmation(writer, plan); err == nil {
				t.Fatalf("expected setupWriteConfirmation failure at write %d", failAt)
			}
		}
	})
}

func TestSetupResolveProjectAndAgentResidualCoverage(t *testing.T) {
	lockAppSeams(t)

	t.Run("project root empty prompt keeps default", func(t *testing.T) {
		repo := t.TempDir()
		if out, err := run("git", "-C", repo, "init"); err != nil {
			t.Fatalf("git init: %v: %s", err, out)
		}
		wd, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		if err := os.Chdir(repo); err != nil {
			t.Fatalf("chdir: %v", err)
		}
		defer func() { _ = os.Chdir(wd) }()
		root, err := setupResolveProjectRoot(context.Background(), setupOptions{}, newSetupPrompter(bytes.NewBufferString("\n"), io.Discard))
		if err != nil || root == "" {
			t.Fatalf("expected default project root, got %q err=%v", root, err)
		}
	})

	t.Run("agent prompt empty keeps defaults", func(t *testing.T) {
		origLookPath := setupLookPathFn
		defer func() { setupLookPathFn = origLookPath }()
		setupLookPathFn = func(name string) (string, error) {
			if name == "codex" {
				return "/usr/bin/codex", nil
			}
			return "", os.ErrNotExist
		}
		selected, err := setupResolveAgents(setupOptions{}, newSetupPrompter(bytes.NewBufferString("\n"), io.Discard))
		if err != nil || len(selected) != 0 {
			t.Fatalf("expected skip-for-now selected agents, got %+v err=%v", selected, err)
		}
	})

	t.Run("setupHaspCommandPath prefers lookpath then executable", func(t *testing.T) {
		origLook := setupLookPathFn
		origExec := setupExecutableFn
		defer func() {
			setupLookPathFn = origLook
			setupExecutableFn = origExec
		}()

		setupLookPathFn = func(string) (string, error) { return "/opt/homebrew/bin/hasp", nil }
		setupExecutableFn = func() (string, error) { return "/tmp/fallback-hasp", nil }
		if got := setupHaspCommandPath(); got != "/opt/homebrew/bin/hasp" {
			t.Fatalf("expected lookpath result, got %q", got)
		}

		setupLookPathFn = func(string) (string, error) { return "", os.ErrNotExist }
		setupExecutableFn = func() (string, error) { return "/tmp/hasp", nil }
		if got := setupHaspCommandPath(); got != "/tmp/hasp" {
			t.Fatalf("expected executable fallback, got %q", got)
		}

		setupLookPathFn = func(string) (string, error) { return "", os.ErrNotExist }
		setupExecutableFn = func() (string, error) { return "/tmp/fallback-hasp", nil }
		if got := setupHaspCommandPath(); got != "hasp" {
			t.Fatalf("expected generic fallback, got %q", got)
		}
	})

	t.Run("setup visual helpers cover color and empty branches", func(t *testing.T) {
		devnull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
		if err != nil {
			t.Fatalf("open /dev/null: %v", err)
		}
		defer devnull.Close()

		t.Setenv("NO_COLOR", "")
		t.Setenv("TERM", "xterm-256color")
		if !setupWriterSupportsColor(devnull) {
			t.Fatal("expected color support on char-device writer")
		}
		if !strings.Contains(setupStageHeader(devnull, "Title"), "\x1b[1;36m") {
			t.Fatal("expected colored stage header")
		}
		if !strings.Contains(setupSummarySectionHeader(devnull, "Summary"), "\x1b[1m") {
			t.Fatal("expected colored summary section header")
		}
		if !strings.Contains(setupSummaryLead(devnull, "ready"), "\x1b[1;32m") {
			t.Fatal("expected colored summary lead")
		}
		if !strings.Contains(setupSummaryKeyValue(devnull, "Status", "enabled"), "\x1b[1;32m") {
			t.Fatal("expected enabled values to be highlighted")
		}
		if !strings.Contains(setupSummaryKeyValue(devnull, "Path", "~/file"), "\x1b[36m") {
			t.Fatal("expected path values to be highlighted")
		}
		if !strings.Contains(setupSummaryAgentLine(devnull, setupAgentOutcome{
			Label:      "Codex CLI",
			ConfigPath: "/tmp/codex.toml",
			Changed:    false,
		}), "\x1b[2m(unchanged)\x1b[0m") {
			t.Fatal("expected unchanged agent status to be dimmed")
		}
		if !strings.Contains(setupSummaryStepLine(devnull, 2, "next"), "\x1b[1;36m2.\x1b[0m") {
			t.Fatal("expected step index to be highlighted")
		}
		if got := setupStageLine(devnull, ""); got != "" {
			t.Fatalf("expected empty stage line, got %q", got)
		}
		if got := setupStageLine(devnull, "- bullet"); !strings.Contains(got, "- bullet") {
			t.Fatalf("expected dash line preserved as list item, got %q", got)
		}
		if got := setupStageLine(devnull, "2. second"); !strings.Contains(got, "2.") || !strings.Contains(got, "second") {
			t.Fatalf("expected numbered line preserved as numbered item, got %q", got)
		}
		if got := setupStageLine(devnull, "plain line"); !strings.Contains(got, "•") || !strings.Contains(got, "plain line") {
			t.Fatalf("expected plain line to gain setup bullet, got %q", got)
		}
		if got := setupStageLine(devnull, "   config: /tmp/file"); !strings.Contains(got, "config") || !strings.Contains(got, "/tmp/file") {
			t.Fatalf("expected config line preserved and styled, got %q", got)
		}
		if got := setupStageLine(devnull, "   plain indented"); got != "   plain indented" {
			t.Fatalf("expected generic indented line preserved, got %q", got)
		}
		if got := setupStageLine(devnull, "2.second"); !strings.Contains(got, "2.second") {
			t.Fatalf("expected malformed numbered line fallback, got %q", got)
		}
		if kind := setupStageLineKind("1. first"); kind != "numeric" {
			t.Fatalf("expected numeric line kind, got %q", kind)
		}
		if kind := setupStageLineKind(""); kind != "" {
			t.Fatalf("expected empty line kind, got %q", kind)
		}
		if kind := setupStageLineKind("   config: /tmp/file"); kind != "config" {
			t.Fatalf("expected config line kind, got %q", kind)
		}
		if kind := setupStageLineKind("- bullet"); kind != "dash" {
			t.Fatalf("expected dash line kind, got %q", kind)
		}
		if kind := setupStageLineKind("   plain indented"); kind != "indented" {
			t.Fatalf("expected indented line kind, got %q", kind)
		}
		if kind := setupStageLineKind("plain"); kind != "text" {
			t.Fatalf("expected text line kind, got %q", kind)
		}
		if !setupShouldSeparateStageLines("Enter numbers like 1 or 1,3.", "1. Codex CLI") {
			t.Fatal("expected prose-to-numbered separation")
		}
		if !setupShouldSeparateStageLines("3. finish setup", "Press Enter to continue.") {
			t.Fatal("expected numbered-to-prose separation")
		}
		if setupShouldSeparateStageLines("HASP setup will:", "1. choose where local encrypted HASP data lives on this machine") {
			t.Fatal("did not expect separation after a list header line")
		}
		if prefix, rest, ok := setupSplitNumericPrefix("3. third"); !ok || prefix != "3." || rest != "third" {
			t.Fatalf("expected numeric prefix split, got prefix=%q rest=%q ok=%v", prefix, rest, ok)
		}
		if _, _, ok := setupSplitNumericPrefix("plain"); ok {
			t.Fatal("expected non-numbered line to skip numeric split")
		}
		if got := setupSummaryValue(devnull, "unavailable"); !strings.Contains(got, "\x1b[1;33m") {
			t.Fatalf("expected unavailable to be highlighted as warning, got %q", got)
		}
		if got := setupSummaryValue(devnull, "existing"); !strings.Contains(got, "\x1b[1;36m") {
			t.Fatalf("expected existing to be highlighted as neutral status, got %q", got)
		}
		if got := setupSummaryValue(devnull, "plain text"); got != "plain text" {
			t.Fatalf("expected plain values to stay plain, got %q", got)
		}

		t.Setenv("NO_COLOR", "1")
		if setupWriterSupportsColor(devnull) {
			t.Fatal("expected NO_COLOR to disable color support")
		}
		t.Setenv("NO_COLOR", "")
		t.Setenv("TERM", "dumb")
		if setupWriterSupportsColor(devnull) {
			t.Fatal("expected TERM=dumb to disable color support")
		}
		t.Setenv("TERM", "xterm-256color")

		var nilFile *os.File
		if setupWriterSupportsColor(nilFile) {
			t.Fatal("expected nil *os.File writer to disable color support")
		}

		tempFile, err := os.CreateTemp(t.TempDir(), "setup-visual-*.txt")
		if err != nil {
			t.Fatalf("create temp file: %v", err)
		}
		if setupWriterSupportsColor(tempFile) {
			t.Fatal("expected regular file writer to be treated as non-color")
		}
		if got := setupStyle(tempFile, "1;32", "text"); got != "text" {
			t.Fatalf("expected non-color style passthrough, got %q", got)
		}
		if err := setupWriteKeyValueBlock(tempFile, "Empty"); err != nil {
			t.Fatalf("expected empty key/value block to be a no-op, got %v", err)
		}
		if err := tempFile.Close(); err != nil {
			t.Fatalf("close temp file: %v", err)
		}
		if setupWriterSupportsColor(tempFile) {
			t.Fatal("expected closed file stat failure to disable color support")
		}
	})
}

func TestSetupWriteAgentConfigsResidualCoverage(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	origRead := setupReadFileFn
	origCreateTemp := setupCreateTempFn
	defer func() {
		setupReadFileFn = origRead
		setupCreateTempFn = origCreateTemp
	}()

	t.Run("existing read failure", func(t *testing.T) {
		path := filepath.Join(homeDir, ".claude.json")
		if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		setupReadFileFn = func(string) ([]byte, error) { return nil, errors.New("read fail") }
		if _, err := setupWriteAgentConfigs([]setupAgentSpec{{
			ID:         "claude-code",
			Format:     "json",
			ConfigPath: func(string) string { return path },
		}}, filepath.Join(homeDir, ".hasp")); err == nil || !strings.Contains(err.Error(), "read fail") {
			t.Fatalf("expected read failure, got %v", err)
		}
		setupReadFileFn = origRead
	})

	t.Run("malformed existing json", func(t *testing.T) {
		path := filepath.Join(homeDir, ".cursor", "mcp.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("mkdir config dir: %v", err)
		}
		if err := os.WriteFile(path, []byte(`{bad`), 0o600); err != nil {
			t.Fatalf("write malformed config: %v", err)
		}
		if _, err := setupWriteAgentConfigs([]setupAgentSpec{{
			ID:         "cursor",
			Format:     "json",
			ConfigPath: func(string) string { return path },
		}}, filepath.Join(homeDir, ".hasp")); err == nil {
			t.Fatal("expected malformed json error")
		}
	})

	t.Run("atomic write failure propagates", func(t *testing.T) {
		path := filepath.Join(homeDir, ".cursor", "fresh.json")
		setupCreateTempFn = func(string, string) (*os.File, error) { return nil, errors.New("temp fail") }
		if _, err := setupWriteAgentConfigs([]setupAgentSpec{{
			ID:         "cursor",
			Format:     "json",
			ConfigPath: func(string) string { return path },
		}}, filepath.Join(homeDir, ".hasp")); err == nil || !strings.Contains(err.Error(), "temp fail") {
			t.Fatalf("expected atomic write failure, got %v", err)
		}
	})
}
