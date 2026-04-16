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

type setupNthWriteErrWriter struct {
	allow int
	err   error
}

func (w *setupNthWriteErrWriter) Write(p []byte) (int, error) {
	if w.allow > 0 {
		w.allow--
		return len(p), nil
	}
	return 0, w.err
}

type unavailableSetupKeyring struct{}

func (unavailableSetupKeyring) Set(context.Context, string, string, string) error {
	return store.ErrKeyringUnavailable
}
func (unavailableSetupKeyring) Get(string, string) (string, error) {
	return "", store.ErrKeyringUnavailable
}
func (unavailableSetupKeyring) Delete(string, string) error { return store.ErrKeyringUnavailable }

func TestRunSetupAdditionalCoverageBranches(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	haspHome := filepath.Join(t.TempDir(), "hasp-home")
	projectRoot := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))
	t.Setenv("SETUP_PW", "correct horse battery staple")

	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	origHome := setupUserHomeDirFn
	origLookPath := setupLookPathFn
	origNewStore := newVaultStoreFn
	origOpenStore := openStoreWithPasswordFn
	defer func() {
		setupUserHomeDirFn = origHome
		setupLookPathFn = origLookPath
		newVaultStoreFn = origNewStore
		openStoreWithPasswordFn = origOpenStore
	}()
	setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
	setupLookPathFn = func(string) (string, error) { return "", os.ErrNotExist }

	baseOpts := setupOptions{
		NonInteractive:          true,
		HaspHome:                haspHome,
		Repo:                    projectRoot,
		Agents:                  setupAgentFlags{"codex-cli"},
		PasswordEnv:             "SETUP_PW",
		InstallHooks:            setupOptionalBool{set: true, value: false},
		EnableConvenienceUnlock: setupOptionalBool{set: true, value: false},
		OverwriteExistingConfig: setupOptionalBool{set: true, value: true},
		DefaultPolicy:           store.PolicySession,
	}

	t.Run("home inside repo fails validation", func(t *testing.T) {
		opts := baseOpts
		canonicalRoot, err := filepath.EvalSymlinks(projectRoot)
		if err != nil {
			t.Fatalf("eval symlinks project root: %v", err)
		}
		opts.HaspHome = filepath.Join(canonicalRoot, ".hasp")
		if _, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "inside the project directory") {
			t.Fatalf("expected home-path validation error, got %v", err)
		}
	})

	t.Run("empty selected agents trips guard", func(t *testing.T) {
		opts := baseOpts
		opts.Agents = setupAgentFlags{""}
		if _, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "at least one supported agent") {
			t.Fatalf("expected empty selected-agents error, got %v", err)
		}
	})

	t.Run("existing config requires overwrite approval", func(t *testing.T) {
		opts := baseOpts
		opts.Agents = setupAgentFlags{"claude-code"}
		opts.OverwriteExistingConfig = setupOptionalBool{}
		configPath := filepath.Join(homeDir, ".claude.json")
		if err := os.WriteFile(configPath, []byte(`{}`), 0o600); err != nil {
			t.Fatalf("write existing config: %v", err)
		}
		if _, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "--overwrite-existing-config=true|false") {
			t.Fatalf("expected overwrite approval error, got %v", err)
		}
	})

	t.Run("existing config denied", func(t *testing.T) {
		opts := baseOpts
		opts.Agents = setupAgentFlags{"claude-code"}
		opts.OverwriteExistingConfig = setupOptionalBool{set: true, value: false}
		configPath := filepath.Join(homeDir, ".claude.json")
		if err := os.WriteFile(configPath, []byte(`{}`), 0o600); err != nil {
			t.Fatalf("write existing config: %v", err)
		}
		if _, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "overwrite approval was denied") {
			t.Fatalf("expected overwrite denied error, got %v", err)
		}
	})

	t.Run("preview import failure propagates", func(t *testing.T) {
		opts := baseOpts
		opts.ImportPath = filepath.Join(t.TempDir(), ".env")
		opts.ImportFormat = "env"
		if err := os.WriteFile(opts.ImportPath, []byte("BROKEN"), 0o600); err != nil {
			t.Fatalf("write broken import: %v", err)
		}
		newVaultStoreFn = func() (*store.Store, error) { return store.New(&memorySetupKeyring{}) }
		if _, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard); err == nil {
			t.Fatal("expected preview import failure")
		}
	})

	t.Run("convenience unavailable is recorded", func(t *testing.T) {
		opts := baseOpts
		opts.EnableConvenienceUnlock = setupOptionalBool{set: true, value: true}
		opts.HaspHome = filepath.Join(t.TempDir(), "vault")
		newVaultStoreFn = func() (*store.Store, error) { return store.New(unavailableSetupKeyring{}) }
		summary, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard)
		if err != nil {
			t.Fatalf("run setup with unavailable keyring: %v", err)
		}
		if summary.ConvenienceUnlock != "unavailable" {
			t.Fatalf("expected unavailable convenience unlock, got %+v", summary)
		}
	})

	t.Run("resolve home failure propagates", func(t *testing.T) {
		origHomeEnv := os.Getenv("HOME")
		origXDG := os.Getenv("XDG_CONFIG_HOME")
		t.Setenv("HOME", "")
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Cleanup(func() {
			t.Setenv("HOME", origHomeEnv)
			t.Setenv("XDG_CONFIG_HOME", origXDG)
		})
		opts := baseOpts
		if _, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard); err == nil {
			t.Fatal("expected setupResolveHome failure to propagate")
		}
	})

	t.Run("resolve agents failure propagates", func(t *testing.T) {
		opts := baseOpts
		opts.Agents = setupAgentFlags{"missing"}
		if _, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "unsupported setup agent") {
			t.Fatalf("expected setupResolveAgents failure, got %v", err)
		}
	})

	t.Run("validate non-interactive failure propagates", func(t *testing.T) {
		opts := baseOpts
		opts.PasswordEnv = ""
		if _, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "--master-password-env") {
			t.Fatalf("expected validateSetupNonInteractive failure, got %v", err)
		}
	})

	t.Run("ensure handle failure propagates", func(t *testing.T) {
		opts := baseOpts
		opts.HaspHome = filepath.Join(t.TempDir(), "vault")
		newVaultStoreFn = func() (*store.Store, error) { return store.New(&memorySetupKeyring{}) }
		openStoreWithPasswordFn = func(context.Context, *store.Store, string) (*store.Handle, error) {
			return nil, errors.New("open fail")
		}
		if _, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "open fail") {
			t.Fatalf("expected setupEnsureHandle failure, got %v", err)
		}
		openStoreWithPasswordFn = origOpenStore
	})

	t.Run("convenience generic error propagates", func(t *testing.T) {
		opts := baseOpts
		opts.EnableConvenienceUnlock = setupOptionalBool{set: true, value: true}
		opts.HaspHome = filepath.Join(t.TempDir(), "vault")
		newVaultStoreFn = func() (*store.Store, error) { return store.New(&memorySetupKeyring{}) }
		openStoreWithPasswordFn = func(ctx context.Context, vaultStore *store.Store, password string) (*store.Handle, error) {
			handle, err := origOpenStore(ctx, vaultStore, password)
			if err != nil {
				return nil, err
			}
			if err := os.Remove(filepath.Join(opts.HaspHome, "vault.json.enc")); err != nil {
				return nil, err
			}
			return handle, nil
		}
		if _, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard); err == nil {
			t.Fatal("expected convenience unlock generic failure")
		}
		openStoreWithPasswordFn = origOpenStore
	})
}

func TestSetupResolveBoolOptionsAndNonInteractiveCoverage(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	configPath := filepath.Join(homeDir, ".claude.json")
	if err := os.WriteFile(configPath, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	agents := []setupAgentSpec{{
		ID:     "claude-code",
		Format: "json",
		ConfigPath: func(string) string {
			return configPath
		},
	}}

	t.Run("non-interactive missing prompts", func(t *testing.T) {
		cases := []struct {
			name string
			opts setupOptions
			want string
		}{
			{name: "install hooks", opts: setupOptions{NonInteractive: true}, want: "--install-hooks"},
			{name: "convenience unlock", opts: setupOptions{NonInteractive: true, InstallHooks: setupOptionalBool{set: true, value: false}}, want: "--enable-convenience-unlock"},
			{name: "overwrite existing config", opts: setupOptions{NonInteractive: true, InstallHooks: setupOptionalBool{set: true, value: false}, EnableConvenienceUnlock: setupOptionalBool{set: true, value: false}}, want: "--overwrite-existing-config"},
		}
		for _, tc := range cases {
			if err := setupResolveBoolOptions(&tc.opts, newSetupPrompter(bytes.NewBuffer(nil), io.Discard), agents); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s: expected %q error, got %v", tc.name, tc.want, err)
			}
		}
	})

	t.Run("prompt failures propagate", func(t *testing.T) {
		cases := []struct {
			name   string
			opts   setupOptions
			prompt *setupPrompter
		}{
			{name: "install hooks", opts: setupOptions{}, prompt: newSetupPrompter(setupErrReader{}, io.Discard)},
			{name: "convenience unlock", opts: setupOptions{InstallHooks: setupOptionalBool{set: true, value: false}}, prompt: newSetupPrompter(setupErrReader{}, io.Discard)},
			{name: "import path", opts: setupOptions{InstallHooks: setupOptionalBool{set: true, value: false}, EnableConvenienceUnlock: setupOptionalBool{set: true, value: false}}, prompt: newSetupPrompter(setupErrReader{}, io.Discard)},
			{name: "overwrite existing config", opts: setupOptions{InstallHooks: setupOptionalBool{set: true, value: false}, EnableConvenienceUnlock: setupOptionalBool{set: true, value: false}, ImportPath: "already-set"}, prompt: newSetupPrompter(bytes.NewBufferString(""), errWriter{err: errors.New("write fail")})},
		}
		for _, tc := range cases {
			if err := setupResolveBoolOptions(&tc.opts, tc.prompt, agents); err == nil {
				t.Fatalf("%s: expected prompt error", tc.name)
			}
		}
	})

	t.Run("validate non-interactive distinct errors", func(t *testing.T) {
		cases := []struct {
			name string
			opts setupOptions
			want string
		}{
			{name: "missing home", opts: setupOptions{NonInteractive: true}, want: "--hasp-home"},
			{name: "missing repo", opts: setupOptions{NonInteractive: true, HaspHome: "/tmp/hasp"}, want: "--repo"},
			{name: "missing agent", opts: setupOptions{NonInteractive: true, HaspHome: "/tmp/hasp", Repo: "/tmp/repo"}, want: "--agent"},
			{name: "missing password", opts: setupOptions{NonInteractive: true, HaspHome: "/tmp/hasp", Repo: "/tmp/repo", Agents: setupAgentFlags{"codex-cli"}}, want: "--master-password-env"},
		}
		for _, tc := range cases {
			if err := validateSetupNonInteractive(tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s: expected %q error, got %v", tc.name, tc.want, err)
			}
		}
	})
}

func TestSetupResolvePasswordAdditionalCoverage(t *testing.T) {
	lockAppSeams(t)

	t.Run("stdin read error", func(t *testing.T) {
		if _, _, err := setupResolvePassword(newSetupPrompter(errReader{err: errors.New("stdin fail")}, io.Discard), setupOptions{PasswordStdin: true}, t.TempDir()); err == nil || !strings.Contains(err.Error(), "stdin fail") {
			t.Fatalf("expected stdin read failure, got %v", err)
		}
	})

	t.Run("existing vault empty prompt", func(t *testing.T) {
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, "vault.json.enc"), []byte("x"), 0o600); err != nil {
			t.Fatalf("write fake vault: %v", err)
		}
		if _, _, err := setupResolvePassword(newSetupPrompter(bytes.NewBufferString("\n"), io.Discard), setupOptions{}, home); err == nil || !strings.Contains(err.Error(), "master password is required") {
			t.Fatalf("expected empty existing-vault password error, got %v", err)
		}
	})

	t.Run("existing vault success", func(t *testing.T) {
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, "vault.json.enc"), []byte("x"), 0o600); err != nil {
			t.Fatalf("write fake vault: %v", err)
		}
		password, exists, err := setupResolvePassword(newSetupPrompter(bytes.NewBufferString("existing-password\n"), io.Discard), setupOptions{}, home)
		if err != nil || !exists || password != "existing-password" {
			t.Fatalf("expected existing-vault password success, got %q exists=%v err=%v", password, exists, err)
		}
	})

	t.Run("new vault blank confirmation", func(t *testing.T) {
		if _, _, err := setupResolvePassword(newSetupPrompter(bytes.NewBufferString("\n\n"), io.Discard), setupOptions{}, t.TempDir()); err == nil || !strings.Contains(err.Error(), "master password is required") {
			t.Fatalf("expected blank new-vault password error, got %v", err)
		}
	})
}

func TestSetupImportAndBindAdditionalCoverage(t *testing.T) {
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

	t.Run("bad import content", func(t *testing.T) {
		importPath := filepath.Join(t.TempDir(), ".env")
		if err := os.WriteFile(importPath, []byte("BROKEN"), 0o600); err != nil {
			t.Fatalf("write import file: %v", err)
		}
		if _, err := setupImportAndBind(context.Background(), handle, projectRoot, setupOptions{ImportPath: importPath, ImportFormat: "env"}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard)); err == nil {
			t.Fatal("expected import parse failure")
		}
	})

	t.Run("missing alias item", func(t *testing.T) {
		if _, err := setupImportAndBind(context.Background(), handle, projectRoot, setupOptions{Aliases: map[string]string{"API_TOKEN": "missing"}}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard)); err == nil {
			t.Fatal("expected missing alias item failure")
		}
	})

	t.Run("missing bind item", func(t *testing.T) {
		if _, err := setupImportAndBind(context.Background(), handle, projectRoot, setupOptions{BindItems: []string{"missing"}}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard)); err == nil {
			t.Fatal("expected missing bind item failure")
		}
	})

	t.Run("import path bind failure", func(t *testing.T) {
		importHome := t.TempDir()
		t.Setenv("HASP_HOME", importHome)
		importStore, err := store.New(&memorySetupKeyring{})
		if err != nil {
			t.Fatalf("new import store: %v", err)
		}
		if err := importStore.Init(context.Background(), "correct horse battery staple"); err != nil {
			t.Fatalf("init import store: %v", err)
		}
		importHandle, err := importStore.OpenWithPassword(context.Background(), "correct horse battery staple")
		if err != nil {
			t.Fatalf("open import handle: %v", err)
		}
		importPath := filepath.Join(t.TempDir(), ".env")
		if err := os.WriteFile(importPath, []byte("OPENAI_API_KEY=abc123\n"), 0o600); err != nil {
			t.Fatalf("write import file: %v", err)
		}
		if err := os.RemoveAll(importHome); err != nil {
			t.Fatalf("remove import home: %v", err)
		}
		if _, err := setupImportAndBind(context.Background(), importHandle, "", setupOptions{ImportPath: importPath, ImportFormat: "env"}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard)); err == nil {
			t.Fatal("expected import persistence failure")
		}
	})

	t.Run("finalize bind failure", func(t *testing.T) {
		origInstallHooks := installHooksFn
		defer func() { installHooksFn = origInstallHooks }()
		installHooksFn = func(string) error { return errors.New("hook fail") }
		if _, _, err := setupFinalizeBinding(context.Background(), handle, projectRoot, setupOptions{InstallHooks: setupOptionalBool{set: true, value: true}, DefaultPolicy: store.PolicySession}); err == nil || !strings.Contains(err.Error(), "hook fail") {
			t.Fatal("expected finalize binding failure")
		}
	})
}

func TestSetupHelperCoverageBranches(t *testing.T) {
	lockAppSeams(t)

	t.Run("setupCanHideInputFn branches", func(t *testing.T) {
		if setupCanHideInputFn(nil) {
			t.Fatal("nil file should not be hide-capable")
		}
		tempFile, err := os.CreateTemp(t.TempDir(), "tty-*")
		if err != nil {
			t.Fatalf("create temp: %v", err)
		}
		if setupCanHideInputFn(tempFile) {
			t.Fatal("regular file should not look like a tty")
		}
		if err := tempFile.Close(); err != nil {
			t.Fatalf("close temp: %v", err)
		}
		if setupCanHideInputFn(tempFile) {
			t.Fatal("closed file should not be hide-capable")
		}
	})

	t.Run("setupSttyFn executes", func(t *testing.T) {
		tempFile, err := os.CreateTemp(t.TempDir(), "tty-*")
		if err != nil {
			t.Fatalf("create temp: %v", err)
		}
		defer tempFile.Close()
		_ = setupSttyFn(tempFile, "-echo")
	})

	t.Run("promptString newline write failure", func(t *testing.T) {
		writer := &setupNthWriteErrWriter{allow: 1, err: errors.New("newline fail")}
		if _, err := promptString(newSetupPrompter(bytes.NewBufferString("value\n"), writer), "label", "default"); err == nil || !strings.Contains(err.Error(), "newline fail") {
			t.Fatalf("expected newline writer failure, got %v", err)
		}
	})

	t.Run("promptPassword stty fallback and read error", func(t *testing.T) {
		tempFile, err := os.CreateTemp(t.TempDir(), "tty-*")
		if err != nil {
			t.Fatalf("create temp: %v", err)
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
		password, err := promptPassword(newSetupPrompter(bytes.NewBufferString("visible\n"), io.Discard), "pw")
		if err != nil || password != "visible" {
			t.Fatalf("expected visible fallback password, got %q err=%v", password, err)
		}

		setupSttyFn = func(*os.File, ...string) error { return nil }
		prompt := &setupPrompter{reader: bufio.NewReader(errReader{err: errors.New("hidden read fail")}), out: io.Discard, file: tempFile}
		if _, err := promptPassword(prompt, "pw"); err == nil || !strings.Contains(err.Error(), "hidden read fail") {
			t.Fatalf("expected hidden read failure, got %v", err)
		}
	})

	t.Run("expandHome and withinPath edge branches", func(t *testing.T) {
		origHome := setupUserHomeDirFn
		defer func() { setupUserHomeDirFn = origHome }()

		setupUserHomeDirFn = func() (string, error) { return "/Users/tester", nil }
		if expanded, err := expandHome("~"); err != nil || expanded != "/Users/tester" {
			t.Fatalf("expandHome(~) = %q err=%v", expanded, err)
		}

		setupUserHomeDirFn = func() (string, error) { return "", errors.New("home fail") }
		if _, err := expandHome("~/vault"); err == nil || !strings.Contains(err.Error(), "home fail") {
			t.Fatalf("expected expandHome home-dir failure, got %v", err)
		}

		if withinPath("/tmp/a", "") {
			t.Fatal("expected withinPath false on rel error")
		}
	})

	t.Run("defaultSetupHome final fallback and setupNotes unavailable branch", func(t *testing.T) {
		origHome := setupUserHomeDirFn
		defer func() { setupUserHomeDirFn = origHome }()
		setupUserHomeDirFn = func() (string, error) { return "", errors.New("no home") }
		t.Setenv("HOME", "")
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv(paths.EnvHome, "")
		if got := defaultSetupHome(); got != ".hasp" {
			t.Fatalf("expected .hasp fallback, got %q", got)
		}

		notes := setupNotes([]setupAgentSpec{{ID: "codex-cli"}}, false, setupOptions{}, "unavailable")
		joined := strings.Join(notes, "\n")
		if !strings.Contains(joined, "keyring was unavailable") {
			t.Fatalf("expected unavailable note, got %v", notes)
		}
	})

	t.Run("selectSetupAgents blank and setupAgentBinary default", func(t *testing.T) {
		selected, err := selectSetupAgents(setupSupportedAgents(), []string{"", "cursor"})
		if err != nil || len(selected) != 1 || selected[0].ID != "cursor" {
			t.Fatalf("unexpected selected agents: %+v err=%v", selected, err)
		}
		if setupAgentBinary("custom-agent") != "custom-agent" {
			t.Fatal("expected passthrough agent binary mapping")
		}
	})
}

func TestSetupResolveHomeAdditionalCoverage(t *testing.T) {
	lockAppSeams(t)

	t.Run("defaultSetupHome falls back to literal", func(t *testing.T) {
		origHome := setupUserHomeDirFn
		defer func() { setupUserHomeDirFn = origHome }()
		setupUserHomeDirFn = func() (string, error) { return "", errors.New("no home") }
		t.Setenv("HOME", "")
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv(paths.EnvHome, "")
		if got := defaultSetupHome(); got != ".hasp" {
			t.Fatalf("expected literal .hasp, got %q", got)
		}
	})

	t.Run("prompt error propagates", func(t *testing.T) {
		userHome := t.TempDir()
		configHome := t.TempDir()
		t.Setenv("HOME", userHome)
		t.Setenv("XDG_CONFIG_HOME", configHome)
		origHome := setupUserHomeDirFn
		defer func() { setupUserHomeDirFn = origHome }()
		setupUserHomeDirFn = func() (string, error) { return userHome, nil }
		if _, _, err := setupResolveHome(setupOptions{}, newSetupPrompter(setupErrReader{}, io.Discard)); err == nil {
			t.Fatal("expected prompt read failure")
		}
	})

	t.Run("config path failure", func(t *testing.T) {
		origHomeEnv := os.Getenv("HOME")
		origXDG := os.Getenv("XDG_CONFIG_HOME")
		t.Setenv("HOME", "")
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Cleanup(func() {
			t.Setenv("HOME", origHomeEnv)
			t.Setenv("XDG_CONFIG_HOME", origXDG)
		})
		if _, _, err := setupResolveHome(setupOptions{HaspHome: "/tmp/hasp"}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard)); err == nil {
			t.Fatal("expected config path failure")
		}
	})

	t.Run("abs and expand errors", func(t *testing.T) {
		origHome := setupUserHomeDirFn
		origAbs := setupAbsFn
		defer func() { setupUserHomeDirFn = origHome }()
		defer func() { setupAbsFn = origAbs }()
		setupUserHomeDirFn = func() (string, error) { return "", errors.New("expand fail") }
		if _, _, err := setupResolveHome(setupOptions{}, newSetupPrompter(bytes.NewBufferString("~/vault\n"), io.Discard)); err == nil || !strings.Contains(err.Error(), "expand fail") {
			t.Fatalf("expected interactive expand error, got %v", err)
		}
		setupAbsFn = func(string) (string, error) { return "", errors.New("abs fail") }
		if _, _, err := setupResolveHome(setupOptions{HaspHome: "."}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard)); err == nil {
			t.Fatal("expected explicit-home abs failure")
		}
	})
}

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
		origCanon := setupCanonicalProjectRoot
		defer func() {
			setupUserHomeDirFn = origHome
			newVaultStoreFn = origNewStore
			setupEnableConvenienceUnlockFn = origEnable
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

		setupLookPathFn = func(string) (string, error) { return "", os.ErrNotExist }
		setupUserHomeDirFn = func() (string, error) { return t.TempDir(), nil }
		if _, err := setupResolveAgents(setupOptions{NonInteractive: true}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard)); err == nil || !strings.Contains(err.Error(), "--agent") {
			t.Fatalf("expected non-interactive agents failure, got %v", err)
		}
		if _, err := setupResolveAgents(setupOptions{}, newSetupPrompter(setupErrReader{}, io.Discard)); err == nil {
			t.Fatal("expected interactive agent prompt failure")
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

		t.Setenv("HASP_HOME", t.TempDir())
		vaultStore, err := store.New(&memorySetupKeyring{})
		if err != nil {
			t.Fatalf("new store: %v", err)
		}
		if _, _, err := setupEnsureHandle(context.Background(), vaultStore, "", false); err == nil || !strings.Contains(err.Error(), "master password is required") {
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
		if err != nil || len(selected) == 0 {
			t.Fatalf("expected default selected agents, got %+v err=%v", selected, err)
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
		}}, ""); err == nil || !strings.Contains(err.Error(), "read fail") {
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
		}}, ""); err == nil {
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
		}}, ""); err == nil || !strings.Contains(err.Error(), "temp fail") {
			t.Fatalf("expected atomic write failure, got %v", err)
		}
	})
}
