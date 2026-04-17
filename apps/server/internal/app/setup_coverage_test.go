package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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

type setupCountWriter struct {
	writes int
}

func (w *setupCountWriter) Write(p []byte) (int, error) {
	w.writes++
	return len(p), nil
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
			{name: "overwrite existing config", opts: setupOptions{NonInteractive: true}, want: "--overwrite-existing-config"},
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
			{name: "auto protect", opts: setupOptions{}, prompt: newSetupPrompter(setupErrReader{}, io.Discard)},
			{name: "auto protect stage writer", opts: setupOptions{}, prompt: newSetupPrompter(bytes.NewBuffer(nil), errWriter{err: errors.New("stage fail")})},
			{name: "install hooks", opts: setupOptions{AutoProtectRepos: setupOptionalBool{set: true, value: false}}, prompt: newSetupPrompter(setupErrReader{}, io.Discard)},
			{name: "convenience unlock", opts: setupOptions{AutoProtectRepos: setupOptionalBool{set: true, value: true}, InstallHooks: setupOptionalBool{set: true, value: false}}, prompt: newSetupPrompter(setupErrReader{}, io.Discard)},
			{name: "import path", opts: setupOptions{AutoProtectRepos: setupOptionalBool{set: true, value: true}, InstallHooks: setupOptionalBool{set: true, value: false}, EnableConvenienceUnlock: setupOptionalBool{set: true, value: false}}, prompt: newSetupPrompter(setupErrReader{}, io.Discard)},
			{name: "overwrite existing config", opts: setupOptions{AutoProtectRepos: setupOptionalBool{set: true, value: true}, InstallHooks: setupOptionalBool{set: true, value: false}, EnableConvenienceUnlock: setupOptionalBool{set: true, value: false}, ImportPath: "already-set"}, prompt: newSetupPrompter(bytes.NewBufferString(""), errWriter{err: errors.New("write fail")})},
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
			{name: "missing agent", opts: setupOptions{NonInteractive: true, HaspHome: "/tmp/hasp"}, want: "--agent"},
			{name: "missing password", opts: setupOptions{NonInteractive: true, HaspHome: "/tmp/hasp", Agents: setupAgentFlags{"codex-cli"}}, want: "--master-password-env"},
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

	t.Run("new vault mismatch retries in place", func(t *testing.T) {
		var out bytes.Buffer
		password, exists, err := setupResolvePassword(newSetupPrompter(bytes.NewBufferString("one\ntwo\nfinal-pass\nfinal-pass\n"), &out), setupOptions{}, t.TempDir())
		if err != nil || exists || password != "final-pass" {
			t.Fatalf("expected retry success, got password=%q exists=%v err=%v", password, exists, err)
		}
		if !strings.Contains(out.String(), "did not match") {
			t.Fatalf("expected mismatch retry message, got %q", out.String())
		}
	})

	t.Run("new vault mismatch message write failure", func(t *testing.T) {
		writer := &setupNthWriteErrWriter{allow: 4, err: errors.New("retry write fail")}
		if _, _, err := setupResolvePassword(newSetupPrompter(bytes.NewBufferString("one\ntwo\n"), writer), setupOptions{}, t.TempDir()); err == nil || !strings.Contains(err.Error(), "retry write fail") {
			t.Fatalf("expected retry message write failure, got %v", err)
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

	t.Run("defaultSetupHome uses HASP_HOME env fallback", func(t *testing.T) {
		origHome := setupUserHomeDirFn
		defer func() { setupUserHomeDirFn = origHome }()
		setupUserHomeDirFn = func() (string, error) { return "", errors.New("no home") }
		t.Setenv(paths.EnvHome, "/tmp/hasp-env")
		if got := defaultSetupHome(); got != "/tmp/hasp-env" {
			t.Fatalf("expected env fallback, got %q", got)
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

	t.Run("stage writer failure propagates", func(t *testing.T) {
		userHome := t.TempDir()
		configHome := t.TempDir()
		t.Setenv("HOME", userHome)
		t.Setenv("XDG_CONFIG_HOME", configHome)
		origHome := setupUserHomeDirFn
		defer func() { setupUserHomeDirFn = origHome }()
		setupUserHomeDirFn = func() (string, error) { return userHome, nil }
		if _, _, err := setupResolveHome(setupOptions{}, newSetupPrompter(bytes.NewBuffer(nil), errWriter{err: errors.New("stage fail")})); err == nil {
			t.Fatal("expected stage writer failure")
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

	t.Run("runSetup explicit repo canonical failure", func(t *testing.T) {
		homeDir := t.TempDir()
		t.Setenv("HOME", homeDir)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))
		t.Setenv("SETUP_RESIDUAL_PW", "correct horse battery staple")
		origHome := setupUserHomeDirFn
		origCanon := setupCanonicalProjectRoot
		defer func() {
			setupUserHomeDirFn = origHome
			setupCanonicalProjectRoot = origCanon
		}()
		setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
		setupCanonicalProjectRoot = func(context.Context, string) (string, error) { return "", errors.New("canon fail") }
		if _, err := runSetup(context.Background(), setupOptions{
			HaspHome:                filepath.Join(t.TempDir(), "hasp-home"),
			Repo:                    t.TempDir(),
			Agents:                  setupAgentFlags{"codex-cli"},
			AutoProtectRepos:        setupOptionalBool{set: true, value: true},
			InstallHooks:            setupOptionalBool{set: true, value: true},
			EnableConvenienceUnlock: setupOptionalBool{set: true, value: false},
			PasswordEnv:             "SETUP_RESIDUAL_PW",
			OverwriteExistingConfig: setupOptionalBool{set: true, value: true},
		}, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "canon fail") {
			t.Fatalf("expected explicit repo canonical failure, got %v", err)
		}
	})
}

func TestSetupPresentationHelpers(t *testing.T) {
	t.Run("prompt string with display default", func(t *testing.T) {
		lockAppSeams(t)
		var out bytes.Buffer
		value, err := promptStringWithDisplayDefault(newSetupPrompter(bytes.NewBufferString("\n"), &out), "label", "/Users/tester/.hasp", "~/.hasp")
		if err != nil || value != "/Users/tester/.hasp" {
			t.Fatalf("unexpected value=%q err=%v", value, err)
		}
		if !strings.Contains(out.String(), "[~/.hasp]") {
			t.Fatalf("expected display default in output, got %q", out.String())
		}
	})

	t.Run("display path and convenience defaults", func(t *testing.T) {
		lockAppSeams(t)
		origHome := setupUserHomeDirFn
		origGOOS := setupGOOS
		origTempDir := setupTempDirFn
		origAbs := setupAbsFn
		defer func() {
			setupUserHomeDirFn = origHome
			setupGOOS = origGOOS
			setupTempDirFn = origTempDir
			setupAbsFn = origAbs
		}()
		setupUserHomeDirFn = func() (string, error) { return "/Users/tester", nil }
		if got := setupDisplayPath("/Users/tester"); got != "~" {
			t.Fatalf("unexpected home display path %q", got)
		}
		if got := setupDisplayPath("/Users/tester/.hasp"); got != "~/.hasp" {
			t.Fatalf("unexpected display path %q", got)
		}
		setupUserHomeDirFn = func() (string, error) { return "", errors.New("home fail") }
		if got := setupDisplayPath("/tmp/custom"); got != "/tmp/custom" {
			t.Fatalf("unexpected fallback display path %q", got)
		}
		setupUserHomeDirFn = func() (string, error) { return "/Users/tester", nil }
		if got := setupDisplayPath("/tmp/custom"); got != "/tmp/custom" {
			t.Fatalf("unexpected non-home display path %q", got)
		}
		setupGOOS = "darwin"
		if !defaultSetupConvenienceUnlock() {
			t.Fatal("expected darwin default convenience unlock")
		}
		setupGOOS = "linux"
		if defaultSetupConvenienceUnlock() {
			t.Fatal("expected non-darwin default convenience unlock false")
		}
		tempSaved := t.TempDir()
		setupTempDirFn = func() string { return filepath.Join(t.TempDir(), "elsewhere") }
		if !setupSavedHomeLooksUsable(tempSaved) {
			t.Fatal("expected non-temp-root saved path to be accepted")
		}
		setupTempDirFn = func() string { return filepath.Dir(tempSaved) }
		if setupSavedHomeLooksUsable(tempSaved) {
			t.Fatal("expected temp-root saved path to be rejected")
		}
		if setupSavedHomeLooksUsable(filepath.Join(t.TempDir(), "missing")) {
			t.Fatal("expected missing saved path to be rejected")
		}
		if setupSavedHomeLooksUsable("   ") {
			t.Fatal("expected blank saved path to be rejected")
		}
		parentFile := filepath.Join(t.TempDir(), "parent")
		if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
			t.Fatalf("write parent file: %v", err)
		}
		if setupSavedHomeLooksUsable(filepath.Join(parentFile, "child")) {
			t.Fatal("expected stat error path to be rejected")
		}
		setupTempDirFn = func() string { return "" }
		if !setupSavedHomeLooksUsable(tempSaved) {
			t.Fatal("expected empty temp root to accept saved path")
		}
		setupTempDirFn = func() string { return filepath.Dir(tempSaved) }
		setupAbsFn = func(string) (string, error) { return "", errors.New("abs fail") }
		if setupSavedHomeLooksUsable(tempSaved) {
			t.Fatal("expected abs failure to reject saved path")
		}
		callCount := 0
		setupAbsFn = func(value string) (string, error) {
			callCount++
			if callCount == 1 {
				return value, nil
			}
			return "", errors.New("abs temp fail")
		}
		if setupSavedHomeLooksUsable(tempSaved) {
			t.Fatal("expected temp-root abs failure to reject saved path")
		}
	})

	t.Run("stage and summary writers", func(t *testing.T) {
		lockAppSeams(t)
		var out bytes.Buffer
		if err := setupWriteIntro(&out); err != nil {
			t.Fatalf("write intro: %v", err)
		}
		if err := setupWriteAgentMenu(&out, []setupAgentSpec{
			{ID: "codex-cli", Label: "Codex CLI", ConfigPath: func(string) string { return "/tmp/codex.toml" }},
			{ID: "cursor", Label: "Cursor", ConfigPath: func(string) string { return "/tmp/cursor.json" }},
		}, []string{"cursor"}); err != nil {
			t.Fatalf("write agent menu: %v", err)
		}
		if err := setupWriteSelectedAgents(&out, []setupAgentSpec{{ID: "codex-cli", Label: "Codex CLI", ConfigPath: func(string) string { return "/tmp/codex.toml" }}}); err != nil {
			t.Fatalf("write selected agents: %v", err)
		}
		if err := setupWriteConfirmation(&out, setupPlanPreview{
			HaspHome:                "/tmp/.hasp",
			ProjectRoot:             "/tmp/repo",
			Agents:                  []setupAgentSpec{{ID: "codex-cli", Label: "Codex CLI", ConfigPath: func(string) string { return "/tmp/codex.toml" }}},
			ImportPath:              "/tmp/.env",
			BindImports:             true,
			InstallHooks:            true,
			EnableConvenienceUnlock: true,
			ConfigExists:            true,
		}); err != nil {
			t.Fatalf("write confirmation: %v", err)
		}
		if err := renderSetupSummary(&out, setupSummary{
			HaspHome:          "/tmp/.hasp",
			ConfigPath:        "/tmp/hasp-cli.json",
			InitState:         "created",
			ProjectRoot:       "/tmp/repo",
			ConvenienceUnlock: "enabled",
			Agents: []setupAgentOutcome{{
				Label:      "Codex CLI",
				ConfigPath: "/tmp/codex.toml",
				Changed:    true,
			}},
			NextSteps: []string{"next"},
		}); err != nil {
			t.Fatalf("render summary: %v", err)
		}
		text := out.String()
		if !strings.Contains(text, "HASP setup") || !strings.Contains(text, "Setup complete") || !strings.Contains(text, "Configured agents") || !strings.Contains(text, "Review before apply") {
			t.Fatalf("unexpected presentation output %q", text)
		}
		if !strings.Contains(text, "  • HASP setup will:") {
			t.Fatalf("expected bulleted intro line, got %q", text)
		}
		if !strings.Contains(text, "  1. choose where local encrypted HASP data lives on this machine") {
			t.Fatalf("expected numbered intro step to stay numbered, got %q", text)
		}
		if !strings.Contains(text, "  3. configure selected coding agents to talk to HASP over MCP\n\n  • Press Enter to accept the default shown in brackets.") {
			t.Fatalf("expected spacing between numbered intro list and trailing prose, got %q", text)
		}
		if !strings.Contains(text, "  • Enter numbers like 1 or 1,3. Existing config files are backed up before mutation.\n\n  1. Codex CLI") {
			t.Fatalf("expected spacing between agent prose and numbered list, got %q", text)
		}
		if !strings.Contains(text, "\n✓ HASP is configured for this machine.\n") {
			t.Fatalf("expected summary lead without stage indentation, got %q", text)
		}
		if strings.Contains(text, "\n  HASP is configured for this machine.\n") {
			t.Fatalf("expected summary lead indentation bug to stay fixed, got %q", text)
		}
		if !strings.Contains(text, "\nMachine\n") || !strings.Contains(text, "\nDefaults\n") || !strings.Contains(text, "\nNext steps\n") {
			t.Fatalf("expected grouped summary sections, got %q", text)
		}
		if !strings.Contains(text, "Local HASP data") || !strings.Contains(text, "Automatic repo adoption") {
			t.Fatalf("expected aligned summary key/value rows, got %q", text)
		}
		if !strings.Contains(text, "1. next") {
			t.Fatalf("expected numbered next step, got %q", text)
		}

		countWriter := &setupCountWriter{}
		if err := renderSetupSummary(countWriter, setupSummary{
			HaspHome:          "/tmp/.hasp",
			ConfigPath:        "/tmp/hasp-cli.json",
			InitState:         "created",
			ProjectRoot:       "/tmp/repo",
			ConvenienceUnlock: "enabled",
			Agents: []setupAgentOutcome{{
				Label:      "Codex CLI",
				ConfigPath: "/tmp/codex.toml",
				Changed:    true,
			}},
			NextSteps: []string{"next"},
		}); err != nil {
			t.Fatalf("count render summary: %v", err)
		}
		for failAt := 1; failAt <= countWriter.writes; failAt++ {
			writer := &setupNthWriteErrWriter{allow: failAt - 1, err: errors.New("write fail")}
			err := renderSetupSummary(writer, setupSummary{
				HaspHome:          "/tmp/.hasp",
				ConfigPath:        "/tmp/hasp-cli.json",
				InitState:         "created",
				ProjectRoot:       "/tmp/repo",
				ConvenienceUnlock: "enabled",
				Agents: []setupAgentOutcome{{
					Label:      "Codex CLI",
					ConfigPath: "/tmp/codex.toml",
					Changed:    true,
				}},
				NextSteps: []string{"next"},
			})
			if err == nil {
				t.Fatalf("expected render summary write failure at call %d", failAt)
			}
		}

		countWriter = &setupCountWriter{}
		if err := setupWriteConfirmation(countWriter, setupPlanPreview{
			HaspHome:                "/tmp/.hasp",
			ProjectRoot:             "/tmp/repo",
			Agents:                  []setupAgentSpec{{ID: "codex-cli", Label: "Codex CLI", ConfigPath: func(string) string { return "/tmp/codex.toml" }}},
			InstallHooks:            true,
			EnableConvenienceUnlock: true,
		}); err != nil {
			t.Fatalf("count write confirmation: %v", err)
		}
		for failAt := 1; failAt <= countWriter.writes; failAt++ {
			writer := &setupNthWriteErrWriter{allow: failAt - 1, err: errors.New("write fail")}
			if err := setupWriteConfirmation(writer, setupPlanPreview{
				HaspHome:                "/tmp/.hasp",
				ProjectRoot:             "/tmp/repo",
				Agents:                  []setupAgentSpec{{ID: "codex-cli", Label: "Codex CLI", ConfigPath: func(string) string { return "/tmp/codex.toml" }}},
				InstallHooks:            true,
				EnableConvenienceUnlock: true,
			}); err == nil {
				t.Fatalf("expected write confirmation failure at call %d", failAt)
			}
		}
		out.Reset()
		if err := renderSetupSummary(&out, setupSummary{
			HaspHome:          "/tmp/.hasp",
			ConfigPath:        "/tmp/hasp-cli.json",
			InitState:         "created",
			ProjectRoot:       "/tmp/repo",
			ConvenienceUnlock: "enabled",
			Agents: []setupAgentOutcome{{
				Label:      "Codex CLI",
				ConfigPath: "/tmp/codex.toml",
				Changed:    false,
			}},
		}); err != nil {
			t.Fatalf("render summary unchanged agent: %v", err)
		}
		if !strings.Contains(out.String(), "(unchanged)") {
			t.Fatalf("expected unchanged agent suffix, got %q", out.String())
		}

		out.Reset()
		if err := setupWriteConfirmation(&out, setupPlanPreview{
			HaspHome:                "/tmp/.hasp",
			ImportPath:              "/tmp/.env",
			BindImports:             true,
			AutoProtectRepos:        false,
			InstallHooks:            false,
			EnableConvenienceUnlock: false,
		}); err != nil {
			t.Fatalf("write confirmation with import preview: %v", err)
		}
		if !strings.Contains(out.String(), "Import during setup") || !strings.Contains(out.String(), "Bind imported secrets") {
			t.Fatalf("expected confirmation import details, got %q", out.String())
		}
	})

	t.Run("setup command json and human output modes", func(t *testing.T) {
		lockAppSeams(t)
		userHome := t.TempDir()
		haspHome := filepath.Join(t.TempDir(), "hasp-home")
		repo := t.TempDir()
		t.Setenv("HOME", userHome)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(userHome, ".config"))
		t.Setenv("SETUP_MASTER_PASSWORD", "correct horse battery staple")

		origHome := setupUserHomeDirFn
		origLookPath := setupLookPathFn
		defer func() {
			setupUserHomeDirFn = origHome
			setupLookPathFn = origLookPath
		}()
		setupUserHomeDirFn = func() (string, error) { return userHome, nil }
		setupLookPathFn = func(string) (string, error) { return "", os.ErrNotExist }

		var stdout bytes.Buffer
		if err := setupCommand(context.Background(), []string{
			"--non-interactive",
			"--json",
			"--hasp-home", haspHome,
			"--repo", repo,
			"--agent", "codex-cli",
			"--master-password-env", "SETUP_MASTER_PASSWORD",
			"--install-hooks=false",
			"--enable-convenience-unlock=false",
			"--overwrite-existing-config=true",
		}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
			t.Fatalf("setup command json mode: %v", err)
		}
		if !json.Valid(stdout.Bytes()) {
			t.Fatalf("expected json output, got %q", stdout.String())
		}
	})

	t.Run("stage writers and prompt bool branches", func(t *testing.T) {
		lockAppSeams(t)
		if err := setupWriteSelectedAgents(io.Discard, nil); err != nil {
			t.Fatalf("expected empty selected agents writer to succeed, got %v", err)
		}
		if got := setupDefaultAgentIDs(nil); len(got) != 1 || got[0] != "codex-cli" {
			t.Fatalf("unexpected default agent ids %+v", got)
		}
		if got := setupDefaultAgentSelection([]setupAgentSpec{{ID: "codex-cli"}, {ID: "cursor"}}, []string{"cursor"}); got != "2" {
			t.Fatalf("unexpected default agent selection %q", got)
		}
		if got := setupDefaultAgentSelection([]setupAgentSpec{{ID: "codex-cli"}}, []string{"missing"}); got != "1" {
			t.Fatalf("unexpected fallback default agent selection %q", got)
		}
		selection, err := parseSetupAgentMenuSelection([]setupAgentSpec{{ID: "codex-cli"}, {ID: "cursor"}}, "2,codex-cli,2")
		if err != nil || len(selection) != 2 || selection[0] != "cursor" || selection[1] != "codex-cli" {
			t.Fatalf("unexpected parsed selection %+v err=%v", selection, err)
		}
		selection, err = parseSetupAgentMenuSelection([]setupAgentSpec{{ID: "codex-cli"}, {ID: "cursor"}}, " , cursor , ")
		if err != nil || len(selection) != 1 || selection[0] != "cursor" {
			t.Fatalf("unexpected parsed selection with blanks %+v err=%v", selection, err)
		}
		selection, err = parseSetupAgentMenuSelection([]setupAgentSpec{{ID: "codex-cli"}, {ID: "cursor"}}, "cursor,cursor")
		if err != nil || len(selection) != 1 || selection[0] != "cursor" {
			t.Fatalf("unexpected parsed duplicate id selection %+v err=%v", selection, err)
		}
		if _, err := parseSetupAgentMenuSelection([]setupAgentSpec{{ID: "codex-cli"}}, "9"); err == nil {
			t.Fatal("expected invalid menu selection error")
		}
		if _, err := parseSetupAgentMenuSelection([]setupAgentSpec{{ID: "codex-cli"}}, "missing"); err == nil {
			t.Fatal("expected invalid menu token error")
		}
		if setupYesNo(true) != "yes" || setupYesNo(false) != "no" {
			t.Fatal("unexpected yes/no formatting")
		}
		if setupEnabledDisabled(true) != "enabled when available" || setupEnabledDisabled(false) != "disabled" {
			t.Fatal("unexpected enabled/disabled formatting")
		}
		for failAt := 1; failAt <= 3; failAt++ {
			writer := &setupNthWriteErrWriter{allow: failAt - 1, err: errors.New("write fail")}
			if err := setupWriteStage(writer, "Title", "line"); err == nil {
				t.Fatalf("expected setupWriteStage failure at call %d", failAt)
			}
		}
		writer := &setupNthWriteErrWriter{allow: 2, err: errors.New("separator fail")}
		if err := setupWriteStage(writer, "Title", "explanation", "1. step"); err == nil {
			t.Fatal("expected setupWriteStage separator failure")
		}
		writer = &setupNthWriteErrWriter{allow: 0, err: errors.New("write fail")}
		if err := setupWriteSelectedAgents(writer, []setupAgentSpec{{Label: "Codex CLI", ConfigPath: func(string) string { return "/tmp/codex.toml" }}}); err == nil {
			t.Fatal("expected setupWriteSelectedAgents failure")
		}
		writer = &setupNthWriteErrWriter{allow: 0, err: errors.New("write fail")}
		if err := setupWriteAgentMenu(writer, []setupAgentSpec{{Label: "Codex CLI", ConfigPath: func(string) string { return "/tmp/codex.toml" }}}, []string{"codex-cli"}); err == nil {
			t.Fatal("expected setupWriteAgentMenu failure")
		}
		if value, err := promptBool(newSetupPrompter(bytes.NewBufferString("\n"), io.Discard), "label", true); err != nil || !value {
			t.Fatalf("expected blank promptBool to use default true, got %v err=%v", value, err)
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
		setupVerifyConvenienceUnlockFn = func(context.Context, *store.Store) error { return store.ErrKeyringUnavailable }

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
		if _, err := setupResolveAgents(setupOptions{NonInteractive: true}, newSetupPrompter(bytes.NewBuffer(nil), io.Discard)); err == nil || !strings.Contains(err.Error(), "--agent") {
			t.Fatalf("expected non-interactive agents failure, got %v", err)
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
