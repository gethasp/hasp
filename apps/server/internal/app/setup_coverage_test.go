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
		summary, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard)
		if err != nil {
			t.Fatalf("expected machine-only setup success, got %v", err)
		}
		if len(summary.Agents) != 0 {
			t.Fatalf("expected zero configured agents, got %+v", summary.Agents)
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
		if _, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "--overwrite-existing-config=always|never") {
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
		if _, err := runSetup(context.Background(), opts, bytes.NewBuffer(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "HASP_MASTER_PASSWORD") {
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
			{name: "missing password", opts: setupOptions{NonInteractive: true, HaspHome: "/tmp/hasp"}, want: "HASP_MASTER_PASSWORD"},
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
		var out bytes.Buffer
		origCanHide := setupCanHideInputFn
		defer func() { setupCanHideInputFn = origCanHide }()
		setupCanHideInputFn = func(*os.File) bool { return true }
		pwFile, err := os.CreateTemp(t.TempDir(), "existing-vault-password")
		if err != nil {
			t.Fatalf("create password file: %v", err)
		}
		defer pwFile.Close()
		if _, err := pwFile.WriteString("\nexisting-password\n"); err != nil {
			t.Fatalf("seed password file: %v", err)
		}
		if _, err := pwFile.Seek(0, 0); err != nil {
			t.Fatalf("rewind password file: %v", err)
		}
		password, exists, err := setupResolvePassword(newSetupPrompter(pwFile, &out), setupOptions{}, home)
		if err != nil || !exists || password != "existing-password" {
			t.Fatalf("expected empty existing-vault password retry success, got %q exists=%v err=%v", password, exists, err)
		}
		if !strings.Contains(out.String(), "Master password is required. Try again.") {
			t.Fatalf("expected empty existing-vault retry message, got %q", out.String())
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

	t.Run("new vault empty prompts retry", func(t *testing.T) {
		var out bytes.Buffer
		password, exists, err := setupResolvePassword(newSetupPrompter(bytes.NewBufferString("\n\ncorrect horse battery staple\ncorrect horse battery staple\n"), &out), setupOptions{}, t.TempDir())
		if err != nil || exists || password != "correct horse battery staple" {
			t.Fatalf("expected empty prompts to retry until password success, got password=%q exists=%v err=%v", password, exists, err)
		}
		if got := strings.Count(out.String(), "Master password is required. Try again."); got != 2 {
			t.Fatalf("expected two empty-password retry messages, got %d in %q", got, out.String())
		}
	})

	t.Run("existing vault visible empty prompt retries", func(t *testing.T) {
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, "vault.json.enc"), []byte("x"), 0o600); err != nil {
			t.Fatalf("write fake vault: %v", err)
		}
		var out bytes.Buffer
		password, exists, err := setupResolvePassword(newSetupPrompter(bytes.NewBufferString("\nexisting-password\n"), &out), setupOptions{}, home)
		if err != nil || !exists || password != "existing-password" {
			t.Fatalf("expected visible empty existing-vault password retry success, got %q exists=%v err=%v", password, exists, err)
		}
		if !strings.Contains(out.String(), "Master password is required. Try again.") {
			t.Fatalf("expected empty existing-vault retry message, got %q", out.String())
		}
	})

	t.Run("new vault mismatch retries in place", func(t *testing.T) {
		var out bytes.Buffer
		password, exists, err := setupResolvePassword(newSetupPrompter(bytes.NewBufferString("one\ntwo\nfinal-password\nfinal-password\n"), &out), setupOptions{}, t.TempDir())
		if err != nil || exists || password != "final-password" {
			t.Fatalf("expected retry success, got password=%q exists=%v err=%v", password, exists, err)
		}
		if !strings.Contains(out.String(), "did not match") {
			t.Fatalf("expected mismatch retry message, got %q", out.String())
		}
	})

	t.Run("new vault weak password retries in place", func(t *testing.T) {
		var out bytes.Buffer
		password, exists, err := setupResolvePassword(newSetupPrompter(bytes.NewBufferString("short\nshort\ncorrect horse battery staple\ncorrect horse battery staple\n"), &out), setupOptions{}, t.TempDir())
		if err != nil || exists || password != "correct horse battery staple" {
			t.Fatalf("expected weak password retry success, got password=%q exists=%v err=%v", password, exists, err)
		}
		if !strings.Contains(out.String(), "master password must be at least") || !strings.Contains(out.String(), "Try again.") {
			t.Fatalf("expected weak password retry message, got %q", out.String())
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

		notes := setupNotes([]setupAgentSpec{{ID: "codex-cli"}}, false, setupOptions{}, "unavailable", "detail")
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
