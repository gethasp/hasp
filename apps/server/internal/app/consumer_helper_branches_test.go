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
	"time"

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestAppConsumerHelperBranches(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault handle: %v", err)
	}
	if _, err := handle.UpsertItem("API_TOKEN", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{}); err != nil {
		t.Fatalf("seed API_TOKEN: %v", err)
	}

	origGet := secretGetItemFn
	origEnsure := ensureSessionAppFn
	origRun := runnerExecuteFn
	origAuth := authorizeItemAppFn
	origGetApp := storeGetAppFn
	origAppExec := appExecuteConsumerFn
	origInstallLauncher := appInstallLauncherFn
	origReadFile := appReadFileFn
	origWriteFile := appWriteFileFn
	origIsCharDevice := secretIsCharDeviceFn
	origShell := appUserShellFn
	defer func() {
		secretGetItemFn = origGet
		ensureSessionAppFn = origEnsure
		runnerExecuteFn = origRun
		authorizeItemAppFn = origAuth
		storeGetAppFn = origGetApp
		appExecuteConsumerFn = origAppExec
		appInstallLauncherFn = origInstallLauncher
		appReadFileFn = origReadFile
		appWriteFileFn = origWriteFile
		secretIsCharDeviceFn = origIsCharDevice
		appUserShellFn = origShell
	}()

	if _, err := appConsumerBindings(handle, mappingFlag{"OPENAI_API_KEY": "MISSING"}, nil, nil); err == nil {
		t.Fatal("expected env binding missing secret failure")
	}
	if _, err := appConsumerBindings(handle, nil, mappingFlag{"CERT_PATH": "MISSING"}, nil); err == nil {
		t.Fatal("expected file binding missing secret failure")
	}
	if _, err := appConsumerBindings(handle, nil, nil, mappingFlag{"DATABASE_URL": "MISSING"}); err == nil {
		t.Fatal("expected dotenv binding missing secret failure")
	}

	consumer := store.AppConsumer{
		Name:        "myapp",
		ProjectRoot: projectRoot,
		Command:     []string{"sh", "-lc", "true"},
		Bindings: []store.AppBinding{
			{SecretName: "API_TOKEN", Delivery: store.AppDeliveryEnv, Target: "OPENAI_API_KEY"},
		},
	}

	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{}, errors.New("session fail")
	}
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, io.Discard, io.Discard, &fakeStarter{}, "run"); err == nil || err.Error() != "session fail" {
		t.Fatalf("expected execute session failure, got %v", err)
	}
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "session-token"}, nil
	}
	authorizeItemAppFn = func(*store.Handle, string, string, store.Item, store.Operation, store.GrantScope, store.GrantScope, time.Duration) (store.Item, error) {
		return store.Item{}, errors.New("authorize fail")
	}
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, io.Discard, io.Discard, &fakeStarter{}, "run"); err == nil || err.Error() != "authorize fail" {
		t.Fatalf("expected execute authorize failure, got %v", err)
	}
	authorizeItemAppFn = origAuth
	secretGetItemFn = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("get fail") }
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, io.Discard, io.Discard, &fakeStarter{}, "run"); err == nil || err.Error() != "get fail" {
		t.Fatalf("expected execute get failure, got %v", err)
	}
	secretGetItemFn = origGet
	consumer.Bindings = []store.AppBinding{{SecretName: "API_TOKEN", Delivery: "bogus", Target: "OPENAI_API_KEY"}}
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, io.Discard, io.Discard, &fakeStarter{}, "run"); err == nil || !strings.Contains(err.Error(), "unsupported app delivery") {
		t.Fatalf("expected execute unsupported delivery failure, got %v", err)
	}
	consumer.Bindings = []store.AppBinding{{SecretName: "API_TOKEN", Delivery: store.AppDeliveryTempDotenv, Target: "DATABASE_URL"}}
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, io.Discard, io.Discard, &fakeStarter{}, "run"); err == nil || !strings.Contains(err.Error(), "dotenv_env") {
		t.Fatalf("expected execute dotenv env failure, got %v", err)
	}
	consumer.DotenvEnv = "ENV_FILE"
	runnerExecuteFn = func(context.Context, runner.Input) (runner.Result, error) {
		return runner.Result{}, errors.New("runner fail")
	}
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, io.Discard, io.Discard, &fakeStarter{}, "run"); err == nil || err.Error() != "runner fail" {
		t.Fatalf("expected execute runner failure, got %v", err)
	}
	runnerExecuteFn = func(context.Context, runner.Input) (runner.Result, error) {
		return runner.Result{Stdout: []byte("abc123")}, nil
	}
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, errWriter{err: errors.New("stdout fail")}, io.Discard, &fakeStarter{}, "run"); err == nil || err.Error() != "stdout fail" {
		t.Fatalf("expected execute stdout failure, got %v", err)
	}
	runnerExecuteFn = func(context.Context, runner.Input) (runner.Result, error) {
		return runner.Result{Stderr: []byte("abc123")}, nil
	}
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, io.Discard, errWriter{err: errors.New("stderr fail")}, &fakeStarter{}, "run"); err == nil || err.Error() != "stderr fail" {
		t.Fatalf("expected execute stderr failure, got %v", err)
	}

	storeGetAppFn = func(*store.Handle, string) (store.AppConsumer, error) { return consumer, nil }
	appExecuteConsumerFn = func(context.Context, *store.Handle, store.AppConsumer, []string, io.Writer, io.Writer, starter, string) (runner.Result, error) {
		return runner.Result{ExitCode: 7}, nil
	}
	if err := appRunCommand(context.Background(), []string{"myapp"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "command exited with code 7") {
		t.Fatalf("expected app run nonzero exit, got %v", err)
	}
	appExecuteConsumerFn = func(context.Context, *store.Handle, store.AppConsumer, []string, io.Writer, io.Writer, starter, string) (runner.Result, error) {
		return runner.Result{}, errors.New("run fail")
	}
	if err := appRunCommand(context.Background(), []string{"myapp"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || err.Error() != "run fail" {
		t.Fatalf("expected app run execution failure, got %v", err)
	}

	appUserShellFn = func() string { return "" }
	appExecuteConsumerFn = func(_ context.Context, _ *store.Handle, _ store.AppConsumer, command []string, _ io.Writer, _ io.Writer, _ starter, _ string) (runner.Result, error) {
		if len(command) != 2 || command[0] != "/bin/sh" || command[1] != "-l" {
			t.Fatalf("expected default shell command, got %+v", command)
		}
		return runner.Result{ExitCode: 9}, nil
	}
	if err := appShellCommand(context.Background(), []string{"myapp"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "command exited with code 9") {
		t.Fatalf("expected app shell nonzero exit, got %v", err)
	}
	appExecuteConsumerFn = func(context.Context, *store.Handle, store.AppConsumer, []string, io.Writer, io.Writer, starter, string) (runner.Result, error) {
		return runner.Result{}, errors.New("shell fail")
	}
	if err := appShellCommand(context.Background(), []string{"myapp"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || err.Error() != "shell fail" {
		t.Fatalf("expected app shell execution failure, got %v", err)
	}

	appReadFileFn = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	appWriteFileFn = func(string, []byte, os.FileMode) error { return errors.New("install launcher fail") }
	if err := appInstallCommand(context.Background(), []string{"myapp"}, io.Discard); err == nil || err.Error() != "install launcher fail" {
		t.Fatalf("expected app install launcher failure, got %v", err)
	}
}

func TestAppConsumerLauncherAndRollbackHelpers(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set API_TOKEN: %v", err)
	}

	origResolvePaths := appResolvePathsFn
	origUserHome := appUserHomeDirFn
	origReadFile := appReadFileFn
	origWriteFile := appWriteFileFn
	origRemove := appRemoveFn
	origIsCharDevice := secretIsCharDeviceFn
	origGetApp := storeGetAppFn
	origUpsertApp := storeUpsertAppFn
	origDeleteApp := storeDeleteAppFn
	defer func() {
		appResolvePathsFn = origResolvePaths
		appUserHomeDirFn = origUserHome
		appReadFileFn = origReadFile
		appWriteFileFn = origWriteFile
		appRemoveFn = origRemove
		storeGetAppFn = origGetApp
		storeUpsertAppFn = origUpsertApp
		storeDeleteAppFn = origDeleteApp
	}()

	if err := validateAppConsumerName(""); err == nil {
		t.Fatal("expected empty app consumer name failure")
	}
	if err := validateAppConsumerName("."); err == nil {
		t.Fatal("expected dot app consumer name failure")
	}
	if err := validateAppConsumerName("bad/name"); err == nil {
		t.Fatal("expected slash app consumer name failure")
	}
	if err := validateAppConsumerName("bad:name"); err == nil {
		t.Fatal("expected punctuation app consumer name failure")
	}
	if err := validateAppConsumerName("good-app_1.2"); err != nil {
		t.Fatalf("expected safe app consumer name success, got %v", err)
	}
	if _, err := installAppLauncher("../bad"); err == nil {
		t.Fatal("expected install app launcher invalid name failure")
	}

	appResolvePathsFn = func() (paths.Paths, error) { return paths.Paths{HomeDir: homeDir}, nil }
	appReadFileFn = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	launcherPath, err := installAppLauncher("helper-app")
	if err != nil {
		t.Fatalf("install app launcher success: %v", err)
	}
	data, err := os.ReadFile(launcherPath)
	if err != nil {
		t.Fatalf("read installed launcher: %v", err)
	}
	if !strings.Contains(string(data), "# hasp-managed launcher") {
		t.Fatalf("expected managed launcher marker, got %q", string(data))
	}

	appReadFileFn = func(string) ([]byte, error) { return nil, errors.New("read launcher fail") }
	if _, err := planAppLauncher("helper-app"); err == nil || err.Error() != "read launcher fail" {
		t.Fatalf("expected launcher read failure, got %v", err)
	}
	appReadFileFn = func(string) ([]byte, error) { return []byte("#!/usr/bin/env bash\n# hasp-managed launcher\n"), nil }
	if _, err := planAppLauncher("helper-app"); err != nil {
		t.Fatalf("expected managed launcher overwrite to succeed, got %v", err)
	}
	appReadFileFn = func(string) ([]byte, error) { return []byte("#!/usr/bin/env bash\nexit 0\n"), nil }
	if _, err := planAppLauncher("helper-app"); err == nil || !strings.Contains(err.Error(), "not managed by hasp") {
		t.Fatalf("expected unmanaged launcher failure, got %v", err)
	}

	restored := 0
	deleted := 0
	storeUpsertAppFn = func(_ *store.Handle, consumer store.AppConsumer) (store.AppConsumer, error) {
		restored++
		return consumer, nil
	}
	storeDeleteAppFn = func(_ *store.Handle, name string) error {
		deleted++
		if name != "new-app" {
			t.Fatalf("unexpected rollback delete name %q", name)
		}
		return nil
	}
	if err := rollbackAppConsumer(nil, true, store.AppConsumer{Name: "existing", Command: []string{"true"}}, "new-app"); err != nil {
		t.Fatalf("expected rollback restore success, got %v", err)
	}
	if err := rollbackAppConsumer(nil, false, store.AppConsumer{}, "new-app"); err != nil {
		t.Fatalf("expected rollback delete success, got %v", err)
	}
	if restored != 1 || deleted != 1 {
		t.Fatalf("expected one restore and one delete rollback, got restore=%d delete=%d", restored, deleted)
	}

	storeGetAppFn = func(_ *store.Handle, name string) (store.AppConsumer, error) {
		if name != "myapp" {
			t.Fatalf("unexpected app consumer lookup name %q", name)
		}
		return store.AppConsumer{Name: "myapp", Command: []string{"true"}, LauncherPath: filepath.Join(homeDir, "bin", "myapp")}, nil
	}
	storeUpsertAppFn = func(_ *store.Handle, consumer store.AppConsumer) (store.AppConsumer, error) {
		if consumer.LauncherPath == "" {
			t.Fatalf("expected existing launcher path to be preserved on reconnect")
		}
		return consumer, nil
	}
	if err := appConnectCommand(context.Background(), []string{"myapp", "--project-root", projectRoot, "--cmd", "true", "--env", "OPENAI_API_KEY=API_TOKEN"}, io.Discard); err != nil {
		t.Fatalf("expected reconnect to preserve existing launcher path, got %v", err)
	}

	storeGetAppFn = func(*store.Handle, string) (store.AppConsumer, error) {
		return store.AppConsumer{}, errors.New("lookup existing consumer fail")
	}
		if err := appConnectCommand(context.Background(), []string{"failingapp", "--cmd", "true", "--env", "OPENAI_API_KEY=API_TOKEN"}, io.Discard); err == nil || err.Error() != "lookup existing consumer fail" {
			t.Fatalf("expected existing consumer lookup failure, got %v", err)
		}
		storeGetAppFn = func(*store.Handle, string) (store.AppConsumer, error) {
			return store.AppConsumer{}, store.ErrConsumerNotFound
		}
		promptFile, err := os.CreateTemp(t.TempDir(), "prompt-error")
	if err != nil {
		t.Fatalf("create prompt error file: %v", err)
	}
	promptPath := promptFile.Name()
	if err := promptFile.Close(); err != nil {
		t.Fatalf("close prompt error file: %v", err)
	}
	secretIsCharDeviceFn = func(*os.File) bool { return true }
	closedPromptFile, err := os.Open(promptPath)
	if err != nil {
		t.Fatalf("reopen prompt error file: %v", err)
	}
	if err := closedPromptFile.Close(); err != nil {
		t.Fatalf("close reopened prompt error file: %v", err)
	}
	if err := appConnectCommandWithInput(context.Background(), []string{"promptfail", "--cmd", "true", "--env", "OPENAI_API_KEY=API_TOKEN"}, closedPromptFile, io.Discard, io.Discard); err == nil {
		t.Fatal("expected launcher prompt read failure")
	}
	secretIsCharDeviceFn = origIsCharDevice
	storeGetAppFn = func(*store.Handle, string) (store.AppConsumer, error) {
		return store.AppConsumer{}, store.ErrConsumerNotFound
	}
	connectDeletes := 0
	connectUpserts := 0
	storeUpsertAppFn = func(_ *store.Handle, consumer store.AppConsumer) (store.AppConsumer, error) {
		connectUpserts++
		return consumer, nil
	}
	storeDeleteAppFn = func(*store.Handle, string) error {
		connectDeletes++
		return nil
	}
	appReadFileFn = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	appWriteFileFn = func(string, []byte, os.FileMode) error { return errors.New("connect launcher write fail") }
	if err := appConnectCommand(context.Background(), []string{"rollbackapp", "--cmd", "true", "--env", "OPENAI_API_KEY=API_TOKEN", "--install"}, io.Discard); err == nil || err.Error() != "connect launcher write fail" {
		t.Fatalf("expected connect launcher write failure, got %v", err)
	}
	if connectUpserts != 1 || connectDeletes != 1 {
		t.Fatalf("expected connect rollback via delete, got upserts=%d deletes=%d", connectUpserts, connectDeletes)
	}
	storeDeleteAppFn = func(*store.Handle, string) error { return errors.New("connect rollback delete fail") }
	if err := appConnectCommand(context.Background(), []string{"rollbackapp2", "--cmd", "true", "--env", "OPENAI_API_KEY=API_TOKEN", "--install"}, io.Discard); err == nil || !strings.Contains(err.Error(), "rollback failed: connect rollback delete fail") {
		t.Fatalf("expected connect rollback failure detail, got %v", err)
	}
	appUserHomeDirFn = func() (string, error) { return "", os.ErrPermission }
	storeDeleteAppFn = func(*store.Handle, string) error { return nil }
	storeUpsertAppFn = func(_ *store.Handle, consumer store.AppConsumer) (store.AppConsumer, error) {
		connectUpserts++
		return consumer, nil
	}
	appReadFileFn = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	appWriteFileFn = os.WriteFile
	if err := appConnectCommandWithInput(context.Background(), []string{"pathfail", "--cmd", "true", "--env", "OPENAI_API_KEY=API_TOKEN", "--install=true", "--add-to-path=true"}, nil, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected connect path update failure, got %v", err)
	}
	storeDeleteAppFn = func(*store.Handle, string) error { return errors.New("connect path rollback fail") }
	if err := appConnectCommandWithInput(context.Background(), []string{"pathfail2", "--cmd", "true", "--env", "OPENAI_API_KEY=API_TOKEN", "--install=true", "--add-to-path=true"}, nil, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "rollback failed: connect path rollback fail") {
		t.Fatalf("expected connect path rollback failure, got %v", err)
	}
	appUserHomeDirFn = origUserHome

	storeGetAppFn = func(*store.Handle, string) (store.AppConsumer, error) {
		return store.AppConsumer{Name: "bad/name", Command: []string{"true"}}, nil
	}
	if err := appInstallCommand(context.Background(), []string{"bad/name"}, io.Discard); err == nil || !strings.Contains(err.Error(), "invalid app consumer name") {
		t.Fatalf("expected install invalid consumer name failure, got %v", err)
	}
	storeGetAppFn = func(*store.Handle, string) (store.AppConsumer, error) {
		return store.AppConsumer{Name: "myapp", Command: []string{"true"}}, nil
	}
	installUpserts := 0
	storeUpsertAppFn = func(_ *store.Handle, consumer store.AppConsumer) (store.AppConsumer, error) {
		installUpserts++
		return consumer, nil
	}
	appReadFileFn = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	appWriteFileFn = func(string, []byte, os.FileMode) error { return errors.New("install launcher write fail") }
	if err := appInstallCommand(context.Background(), []string{"myapp"}, io.Discard); err == nil || err.Error() != "install launcher write fail" {
		t.Fatalf("expected install launcher write failure, got %v", err)
	}
	if installUpserts != 2 {
		t.Fatalf("expected install rollback to restore previous consumer, got upserts=%d", installUpserts)
	}
	installUpserts = 0
	storeUpsertAppFn = func(_ *store.Handle, consumer store.AppConsumer) (store.AppConsumer, error) {
		installUpserts++
		if installUpserts > 1 {
			return store.AppConsumer{}, errors.New("install rollback fail")
		}
		return consumer, nil
	}
	if err := appInstallCommand(context.Background(), []string{"myapp"}, io.Discard); err == nil || !strings.Contains(err.Error(), "rollback failed: install rollback fail") {
		t.Fatalf("expected install rollback failure detail, got %v", err)
	}
	appUserHomeDirFn = func() (string, error) { return "", os.ErrPermission }
	storeUpsertAppFn = func(_ *store.Handle, consumer store.AppConsumer) (store.AppConsumer, error) {
		return consumer, nil
	}
	appWriteFileFn = os.WriteFile
	if err := appInstallCommandWithInput(context.Background(), []string{"myapp", "--add-to-path=true"}, nil, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected install path update failure, got %v", err)
	}
	installPathUpserts := 0
	storeUpsertAppFn = func(_ *store.Handle, consumer store.AppConsumer) (store.AppConsumer, error) {
		installPathUpserts++
		if installPathUpserts > 1 {
			return store.AppConsumer{}, errors.New("install path rollback fail")
		}
		return consumer, nil
	}
	if err := appInstallCommandWithInput(context.Background(), []string{"myapp", "--add-to-path=true"}, nil, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "rollback failed: install path rollback fail") {
		t.Fatalf("expected install path rollback failure, got %v", err)
	}
	appUserHomeDirFn = origUserHome

	storeGetAppFn = func(*store.Handle, string) (store.AppConsumer, error) {
		return store.AppConsumer{Name: "myapp", Command: []string{"true"}, LauncherPath: filepath.Join(homeDir, "bin", "myapp")}, nil
	}
	storeDeleteAppFn = func(*store.Handle, string) error { return nil }
	appRemoveFn = func(string) error { return errors.New("disconnect remove fail") }
	storeUpsertAppFn = func(*store.Handle, store.AppConsumer) (store.AppConsumer, error) {
		return store.AppConsumer{}, errors.New("disconnect rollback fail")
	}
	if err := appDisconnectCommand(context.Background(), []string{"myapp"}, io.Discard); err == nil || !strings.Contains(err.Error(), "rollback failed: disconnect rollback fail") {
		t.Fatalf("expected disconnect rollback failure detail, got %v", err)
	}
}

func TestAgentConsumerConfigRemovalHelpers(t *testing.T) {
	lockAppSeams(t)

	if got := removeCodexMCPServerConfig(nil); got != "" {
		t.Fatalf("expected empty codex removal result, got %q", got)
	}
	if got := removeCodexMCPServerConfig([]byte("[mcp_servers.hasp]\ncommand = \"/bin/hasp\"\n[mcp_servers.other]\ncommand = \"other\"\n")); !strings.Contains(got, "[mcp_servers.other]") || strings.Contains(got, "[mcp_servers.hasp]") {
		t.Fatalf("unexpected codex removal output: %q", got)
	}
	if got := removeCodexMCPServerConfig([]byte("[mcp_servers.hasp]\ncommand = \"/bin/hasp\"\n[mcp_servers.hasp.env]\nHASP_HOME = \"/tmp/hasp\"\n[mcp_servers.other]\ncommand = \"other\"\n")); !strings.Contains(got, "[mcp_servers.other]") || strings.Contains(got, "[mcp_servers.hasp.env]") {
		t.Fatalf("expected hasp env section removal, got %q", got)
	}
	if data, err := removeJSONMCPServerConfig(nil); err != nil || string(data) != "{}\n" {
		t.Fatalf("expected empty json removal result, got %q err=%v", string(data), err)
	}
	if _, err := removeJSONMCPServerConfig([]byte("{")); err == nil {
		t.Fatal("expected invalid json removal failure")
	}
	if data, err := removeJSONMCPServerConfig([]byte(`{"other":true}`)); err != nil || !strings.Contains(string(data), "\"other\"") {
		t.Fatalf("expected json removal to preserve unrelated config, got %q err=%v", string(data), err)
	}
	if data, err := removeJSONMCPServerConfig([]byte(`{"mcpServers":{"hasp":{"command":"hasp"},"other":{"command":"other"}}}`)); err != nil || strings.Contains(string(data), "\"hasp\"") || !strings.Contains(string(data), "\"other\"") {
		t.Fatalf("expected json removal to drop hasp only, got %q err=%v", string(data), err)
	}
	if _, err := removeJSONMCPServerConfig([]byte(`{"mcpServers":"bad"}`)); err == nil {
		t.Fatal("expected invalid mcpServers object failure")
	}

	origRead := setupReadFileFn
	origAtomic := agentAtomicWriteFn
	defer func() {
		setupReadFileFn = origRead
		agentAtomicWriteFn = origAtomic
	}()

	if err := removeAgentConsumerConfig(setupAgentSpec{Format: "json"}, filepath.Join(t.TempDir(), "missing.json")); err != nil {
		t.Fatalf("expected missing config path to noop, got %v", err)
	}
	tomlPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(tomlPath, []byte("[mcp_servers.hasp]\ncommand = \"/bin/hasp\"\n[mcp_servers.hasp.env]\nHASP_HOME = \"/tmp/hasp\"\n[mcp_servers.other]\ncommand = \"other\"\n"), 0o600); err != nil {
		t.Fatalf("write temp toml config: %v", err)
	}
	if err := removeAgentConsumerConfig(setupAgentSpec{Format: "toml"}, tomlPath); err != nil {
		t.Fatalf("expected toml config removal success, got %v", err)
	}
	tomlData, err := os.ReadFile(tomlPath)
	if err != nil {
		t.Fatalf("read updated toml config: %v", err)
	}
	if strings.Contains(string(tomlData), "[mcp_servers.hasp]") || !strings.Contains(string(tomlData), "[mcp_servers.other]") {
		t.Fatalf("unexpected toml removal output: %q", string(tomlData))
	}
	setupReadFileFn = func(string) ([]byte, error) { return nil, errors.New("read fail") }
	if err := removeAgentConsumerConfig(setupAgentSpec{Format: "json"}, "/tmp/config.json"); err == nil || err.Error() != "read fail" {
		t.Fatalf("expected remove config read failure, got %v", err)
	}
	setupReadFileFn = origRead
	bogusPath := filepath.Join(t.TempDir(), "bogus.config")
	if err := os.WriteFile(bogusPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write bogus config: %v", err)
	}
	if err := removeAgentConsumerConfig(setupAgentSpec{Format: "bogus"}, bogusPath); err == nil || !strings.Contains(err.Error(), "unsupported setup config format") {
		t.Fatalf("expected unsupported format failure, got %v", err)
	}
	invalidJSONPath := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(invalidJSONPath, []byte("{"), 0o600); err != nil {
		t.Fatalf("write invalid json config: %v", err)
	}
	if err := removeAgentConsumerConfig(setupAgentSpec{Format: "json"}, invalidJSONPath); err == nil {
		t.Fatal("expected invalid json config removal failure")
	}
	tmpFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(tmpFile, []byte(`{"mcpServers":{"hasp":{"command":"hasp"}}}`), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	agentAtomicWriteFn = func(string, []byte, []byte) (string, bool, error) { return "", false, errors.New("atomic fail") }
	if err := removeAgentConsumerConfig(setupAgentSpec{Format: "json"}, tmpFile); err == nil || err.Error() != "atomic fail" {
		t.Fatalf("expected remove config atomic failure, got %v", err)
	}
}

func TestAgentConsumerHelperBranches(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HOME", homeDir)
	t.Setenv("HASP_HOME", filepath.Join(homeDir, ".hasp"))
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	origOpen := openVaultHandleFn
	origResolvePaths := appResolvePathsFn
	origWriteAgents := setupWriteAgentConfigsFn
	origStoreGet := storeGetAgentFn
	origStoreDelete := storeDeleteAgentFn
	origStoreUpsert := storeUpsertAgentFn
	origRemoveConfig := removeAgentConsumerConfigFn
	origCanon := appCanonicalProjectRootFn
	origResolveBinding := resolveBindingViewAppFn
	defer func() {
		openVaultHandleFn = origOpen
		appResolvePathsFn = origResolvePaths
		setupWriteAgentConfigsFn = origWriteAgents
		storeGetAgentFn = origStoreGet
		storeDeleteAgentFn = origStoreDelete
		storeUpsertAgentFn = origStoreUpsert
		removeAgentConsumerConfigFn = origRemoveConfig
		appCanonicalProjectRootFn = origCanon
		resolveBindingViewAppFn = origResolveBinding
	}()

	if err := agentConnectCommand(context.Background(), []string{"claude-code", "--bad"}, io.Discard); err == nil {
		t.Fatal("expected agent connect parse failure")
	}
	if err := agentConnectCommand(context.Background(), []string{"unknown-agent"}, io.Discard); err == nil {
		t.Fatal("expected agent connect unsupported agent failure")
	}
	if err := agentDisconnectCommand(context.Background(), []string{"claude-code", "--bad"}, io.Discard); err == nil {
		t.Fatal("expected agent disconnect parse failure")
	}

	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault fail") }
	if err := agentConnectCommand(context.Background(), []string{"claude-code"}, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected agent connect open failure, got %v", err)
	}
	openVaultHandleFn = origOpen
	appCanonicalProjectRootFn = func(context.Context, string) (string, error) { return "", errors.New("canonical fail") }
	if err := agentConnectCommand(context.Background(), []string{"claude-code", "--project-root", projectRoot}, io.Discard); err == nil || err.Error() != "canonical fail" {
		t.Fatalf("expected agent connect project-root canonical failure, got %v", err)
	}
	appCanonicalProjectRootFn = origCanon
	resolveBindingViewAppFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("binding fail")
	}
	if err := agentConnectCommand(context.Background(), []string{"claude-code", "--project-root", projectRoot}, io.Discard); err == nil || err.Error() != "binding fail" {
		t.Fatalf("expected agent connect project binding failure, got %v", err)
	}
	resolveBindingViewAppFn = origResolveBinding

	appResolvePathsFn = func() (paths.Paths, error) { return paths.Paths{}, errors.New("paths fail") }
	if err := agentConnectCommand(context.Background(), []string{"claude-code", "--project-root", projectRoot}, io.Discard); err == nil || err.Error() != "paths fail" {
		t.Fatalf("expected agent connect path failure, got %v", err)
	}
	appResolvePathsFn = origResolvePaths
	setupWriteAgentConfigsFn = func([]setupAgentSpec, string) ([]setupAgentOutcome, error) {
		return nil, errors.New("write agent fail")
	}
	if err := agentConnectCommand(context.Background(), []string{"claude-code", "--project-root", projectRoot}, io.Discard); err == nil || err.Error() != "write agent fail" {
		t.Fatalf("expected agent connect config write failure, got %v", err)
	}
	setupWriteAgentConfigsFn = origWriteAgents
	storeUpsertAgentFn = func(*store.Handle, store.AgentConsumer) (store.AgentConsumer, error) {
		return store.AgentConsumer{}, errors.New("upsert agent fail")
	}
	if err := agentConnectCommand(context.Background(), []string{"claude-code", "--project-root", projectRoot}, io.Discard); err == nil || err.Error() != "upsert agent fail" {
		t.Fatalf("expected agent connect store failure, got %v", err)
	}
	storeUpsertAgentFn = origStoreUpsert

	storeGetAgentFn = func(*store.Handle, string) (store.AgentConsumer, error) {
		return store.AgentConsumer{}, errors.New("get agent fail")
	}
	if err := agentDisconnectCommand(context.Background(), []string{"claude-code"}, io.Discard); err == nil || err.Error() != "get agent fail" {
		t.Fatalf("expected agent disconnect get failure, got %v", err)
	}
	storeGetAgentFn = func(*store.Handle, string) (store.AgentConsumer, error) {
		return store.AgentConsumer{Name: "claude-code", AgentID: "unknown", ConfigPath: filepath.Join(homeDir, ".unknown")}, nil
	}
	if err := agentDisconnectCommand(context.Background(), []string{"claude-code"}, io.Discard); err == nil {
		t.Fatal("expected agent disconnect unsupported agent failure")
	}
	storeGetAgentFn = func(*store.Handle, string) (store.AgentConsumer, error) {
		return store.AgentConsumer{Name: "claude-code", AgentID: "claude-code", ConfigPath: filepath.Join(homeDir, ".claude.json")}, nil
	}
	removeAgentConsumerConfigFn = func(setupAgentSpec, string) error { return errors.New("remove config fail") }
	if err := agentDisconnectCommand(context.Background(), []string{"claude-code"}, io.Discard); err == nil || err.Error() != "remove config fail" {
		t.Fatalf("expected agent disconnect config removal failure, got %v", err)
	}
	removeAgentConsumerConfigFn = origRemoveConfig
	storeDeleteAgentFn = func(*store.Handle, string) error { return errors.New("delete agent fail") }
	if err := agentDisconnectCommand(context.Background(), []string{"claude-code"}, io.Discard); err == nil || err.Error() != "delete agent fail" {
		t.Fatalf("expected agent disconnect delete failure, got %v", err)
	}
}
