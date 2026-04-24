package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestAppConsumerRemainingBranches(t *testing.T) {
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

	origGetApp := storeGetAppFn
	origExec := appExecuteConsumerFn
	origInstall := appInstallLauncherFn
	origReadFile := appReadFileFn
	origWriteFile := appWriteFileFn
	origShell := appUserShellFn
	origEnsure := ensureSessionAppFn
	origAuth := authorizeItemAppFn
	origRun := runnerExecuteFn
	origCanon := appCanonicalProjectRootFn
	origResolve := resolveBindingViewAppFn
	origLoadCLIConfig := loadCLIConfigAppFn
	defer func() {
		storeGetAppFn = origGetApp
		appExecuteConsumerFn = origExec
		appInstallLauncherFn = origInstall
		appReadFileFn = origReadFile
		appWriteFileFn = origWriteFile
		appUserShellFn = origShell
		ensureSessionAppFn = origEnsure
		authorizeItemAppFn = origAuth
		runnerExecuteFn = origRun
		appCanonicalProjectRootFn = origCanon
		resolveBindingViewAppFn = origResolve
		loadCLIConfigAppFn = origLoadCLIConfig
	}()

	if got := appUserShellFn(); got != os.Getenv("SHELL") {
		t.Fatalf("expected default shell func to read env, got %q", got)
	}
	if err := appConnectCommand(context.Background(), []string{"myapp", "--bad"}, io.Discard); err == nil {
		t.Fatal("expected app connect parse failure")
	}
	if err := appRunCommand(context.Background(), []string{"myapp", "--bad"}, io.Discard, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected app run parse failure")
	}
	if err := appShellCommand(context.Background(), []string{"myapp", "--bad"}, io.Discard, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected app shell parse failure")
	}
	if err := appInstallCommand(context.Background(), []string{"myapp", "--bad"}, io.Discard); err == nil {
		t.Fatal("expected app install parse failure")
	}
	if err := appDisconnectCommand(context.Background(), []string{"myapp", "--bad"}, io.Discard); err == nil {
		t.Fatal("expected app disconnect parse failure")
	}

	storeGetAppFn = func(*store.Handle, string) (store.AppConsumer, error) {
		return store.AppConsumer{Name: "myapp", ProjectRoot: projectRoot, Command: []string{"true"}}, nil
	}
	appExecuteConsumerFn = func(context.Context, *store.Handle, store.AppConsumer, []string, io.Writer, io.Writer, starter, string) (runner.Result, error) {
		return runner.Result{ExitCode: 7}, nil
	}
	if err := appRunCommand(context.Background(), []string{"myapp"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "code 7") {
		t.Fatalf("expected app run nonzero branch, got %v", err)
	}
	appUserShellFn = func() string { return "" }
	appExecuteConsumerFn = func(_ context.Context, _ *store.Handle, _ store.AppConsumer, command []string, _ io.Writer, _ io.Writer, _ starter, _ string) (runner.Result, error) {
		if len(command) != 2 || command[0] != "/bin/sh" || command[1] != "-l" {
			t.Fatalf("expected default shell command, got %+v", command)
		}
		return runner.Result{ExitCode: 9}, nil
	}
	if err := appShellCommand(context.Background(), []string{"myapp"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || !strings.Contains(err.Error(), "code 9") {
		t.Fatalf("expected app shell nonzero branch, got %v", err)
	}
	appReadFileFn = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	appWriteFileFn = func(string, []byte, os.FileMode) error { return errors.New("install launcher fail") }
	if err := appInstallCommand(context.Background(), []string{"myapp"}, io.Discard); err == nil || err.Error() != "install launcher fail" {
		t.Fatalf("expected app install launcher failure, got %v", err)
	}

	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "session-token"}, nil
	}
	consumer := store.AppConsumer{
		Name:        "myapp",
		ProjectRoot: projectRoot,
		Command:     []string{"true"},
		Bindings: []store.AppBinding{
			{SecretName: "API_TOKEN", Delivery: store.AppDeliveryEnv, Target: "OPENAI_API_KEY"},
		},
	}
	resolveBindingViewAppFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("binding fail")
	}
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, io.Discard, io.Discard, &fakeStarter{}, "run"); err == nil || err.Error() != "binding fail" {
		t.Fatalf("expected execute binding failure, got %v", err)
	}
	resolveBindingViewAppFn = origResolve
	loadCLIConfigAppFn = func() (paths.CLIConfig, error) {
		autoProtect := false
		return paths.CLIConfig{AutoProtectRepos: &autoProtect}, nil
	}
	consumer.ProjectRoot = t.TempDir()
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, io.Discard, io.Discard, &fakeStarter{}, "run"); err == nil || !strings.Contains(err.Error(), "not managed yet") {
		t.Fatalf("expected execute require binding failure, got %v", err)
	}
	consumer.ProjectRoot = projectRoot
	loadCLIConfigAppFn = origLoadCLIConfig
	authorizeItemAppFn = func(*store.Handle, string, string, store.Item, store.Operation, store.GrantScope, store.GrantScope, time.Duration) (store.Item, error) {
		return store.Item{}, errors.New("authorize fail")
	}
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, io.Discard, io.Discard, &fakeStarter{}, "run"); err == nil || err.Error() != "authorize fail" {
		t.Fatalf("expected execute authorize failure, got %v", err)
	}
	authorizeItemAppFn = origAuth
	consumer.Bindings = []store.AppBinding{{SecretName: "API_TOKEN", Delivery: "bogus", Target: "OPENAI_API_KEY"}}
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, io.Discard, io.Discard, &fakeStarter{}, "run"); err == nil || !strings.Contains(err.Error(), "unsupported app delivery") {
		t.Fatalf("expected execute unsupported delivery failure, got %v", err)
	}
	consumer.Bindings = []store.AppBinding{{SecretName: "API_TOKEN", Delivery: store.AppDeliveryTempDotenv, Target: "DATABASE_URL"}}
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, io.Discard, io.Discard, &fakeStarter{}, "run"); err == nil || !strings.Contains(err.Error(), "dotenv_env") {
		t.Fatalf("expected execute missing dotenv env failure, got %v", err)
	}
	consumer.DotenvEnv = "ENV_FILE"
	runnerExecuteFn = func(context.Context, runner.Input) (runner.Result, error) { return runner.Result{}, errors.New("runner fail") }
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, io.Discard, io.Discard, &fakeStarter{}, "run"); err == nil || err.Error() != "runner fail" {
		t.Fatalf("expected execute runner failure, got %v", err)
	}
	runnerExecuteFn = func(context.Context, runner.Input) (runner.Result, error) { return runner.Result{Stdout: []byte("abc123")}, nil }
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, errWriter{err: errors.New("stdout fail")}, io.Discard, &fakeStarter{}, "run"); err == nil || err.Error() != "stdout fail" {
		t.Fatalf("expected execute stdout failure, got %v", err)
	}
	runnerExecuteFn = func(context.Context, runner.Input) (runner.Result, error) { return runner.Result{Stderr: []byte("abc123")}, nil }
	if _, err := executeAppConsumer(context.Background(), handle, consumer, consumer.Command, io.Discard, errWriter{err: errors.New("stderr fail")}, &fakeStarter{}, "run"); err == nil || err.Error() != "stderr fail" {
		t.Fatalf("expected execute stderr failure, got %v", err)
	}
}
