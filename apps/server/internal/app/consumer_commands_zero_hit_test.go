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

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestConsumerCommandDispatchBranches(t *testing.T) {
	lockAppSeams(t)
	starter := &fakeStarter{}
	var appHelp bytes.Buffer
	if err := appConsumerCommand(context.Background(), nil, bytes.NewBuffer(nil), &appHelp, io.Discard, starter); err != nil {
		t.Fatalf("expected app command help, got %v", err)
	}
	if !strings.Contains(appHelp.String(), "Connect a normal application") {
		t.Fatalf("expected app help output, got %q", appHelp.String())
	}
	if err := appConsumerCommand(context.Background(), []string{"bogus"}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter); err == nil {
		t.Fatal("expected unknown app subcommand error")
	}
	var agentHelp bytes.Buffer
	if err := agentConsumerCommand(context.Background(), nil, bytes.NewBuffer(nil), &agentHelp, io.Discard); err != nil {
		t.Fatalf("expected agent command help, got %v", err)
	}
	if !strings.Contains(agentHelp.String(), "Connect a coding agent") {
		t.Fatalf("expected agent help output, got %q", agentHelp.String())
	}
	if err := agentConsumerCommand(context.Background(), []string{"bogus"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected unknown agent subcommand error")
	}
	if name, rest := consumerNameAndArgs(nil); name != "" || rest != nil {
		t.Fatalf("unexpected empty consumer args result %q %+v", name, rest)
	}
	if name, rest := consumerNameAndArgs([]string{"--project-root", "/tmp/repo"}); name != "" || len(rest) != 2 {
		t.Fatalf("unexpected flag-leading consumer args result %q %+v", name, rest)
	}
	if name, rest := consumerNameAndArgs([]string{"myapp", "--install"}); name != "myapp" || len(rest) != 1 || rest[0] != "--install" {
		t.Fatalf("unexpected named consumer args result %q %+v", name, rest)
	}
}

func TestAppConsumerCommandErrorBranches(t *testing.T) {
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
	if _, err := handle.UpsertItem("CERT_FILE", store.ItemKindFile, []byte("certificate"), store.ItemMetadata{}); err != nil {
		t.Fatalf("seed CERT_FILE: %v", err)
	}
	if _, err := handle.UpsertItem("BROKEN_FILE", store.ItemKindFile, []byte("broken"), store.ItemMetadata{}); err != nil {
		t.Fatalf("seed BROKEN_FILE: %v", err)
	}

	origOpen := openVaultHandleFn
	origCanon := appCanonicalProjectRootFn
	origResolveBinding := resolveBindingViewAppFn
	origResolvePaths := appResolvePathsFn
	origMkdir := appMkdirAllFn
	origWriteFile := appWriteFileFn
	origGetApp := storeGetAppFn
	origListApps := storeListAppsFn
	origUpsertApp := storeUpsertAppFn
	origDeleteApp := storeDeleteAppFn
	origExecRun := runnerExecuteFn
	origEnsureSession := ensureSessionAppFn
	origGetItem := secretGetItemFn
	origUpsertItem := secretUpsertItemFn
	origBindItem := secretBindItemAliasFn
	origHideItem := secretHideItemFn
	origDeleteItem := secretDeleteItemFn
	origListItems := secretListItemsFn
	origExposures := secretItemExposuresFn
	defer func() {
		openVaultHandleFn = origOpen
		appCanonicalProjectRootFn = origCanon
		resolveBindingViewAppFn = origResolveBinding
		appResolvePathsFn = origResolvePaths
		appMkdirAllFn = origMkdir
		appWriteFileFn = origWriteFile
		storeGetAppFn = origGetApp
		storeListAppsFn = origListApps
		storeUpsertAppFn = origUpsertApp
		storeDeleteAppFn = origDeleteApp
		runnerExecuteFn = origExecRun
		ensureSessionAppFn = origEnsureSession
		secretGetItemFn = origGetItem
		secretUpsertItemFn = origUpsertItem
		secretBindItemAliasFn = origBindItem
		secretHideItemFn = origHideItem
		secretDeleteItemFn = origDeleteItem
		secretListItemsFn = origListItems
		secretItemExposuresFn = origExposures
	}()

	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault fail") }
	if err := appConnectCommand(context.Background(), []string{"myapp", "--cmd", "true"}, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected connect open failure, got %v", err)
	}
	if err := appRunCommand(context.Background(), []string{"myapp"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected run open failure, got %v", err)
	}
	if err := appShellCommand(context.Background(), []string{"myapp"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected shell open failure, got %v", err)
	}
	if err := appInstallCommand(context.Background(), []string{"myapp"}, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected install open failure, got %v", err)
	}
	if err := appDisconnectCommand(context.Background(), []string{"myapp"}, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected disconnect open failure, got %v", err)
	}
	if err := appListCommand(context.Background(), nil, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected list open failure, got %v", err)
	}
	openVaultHandleFn = origOpen

	if err := appConnectCommand(context.Background(), []string{}, io.Discard); err == nil {
		t.Fatal("expected connect usage failure")
	}
	if err := appConnectCommand(context.Background(), []string{"myapp"}, io.Discard); err == nil {
		t.Fatal("expected missing cmd failure")
	}
	if err := appConnectCommand(context.Background(), []string{"myapp", "--cmd", "true", "--dotenv", "X=API_TOKEN"}, io.Discard); err == nil {
		t.Fatal("expected dotenv-env requirement")
	}
	appCanonicalProjectRootFn = func(context.Context, string) (string, error) { return "", errors.New("canonical fail") }
	if err := appConnectCommand(context.Background(), []string{"myapp", "--project-root", projectRoot, "--cmd", "true"}, io.Discard); err == nil || err.Error() != "canonical fail" {
		t.Fatalf("expected connect project failure, got %v", err)
	}
	appCanonicalProjectRootFn = origCanon
	resolveBindingViewAppFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("binding fail")
	}
	if err := appConnectCommand(context.Background(), []string{"myapp", "--project-root", projectRoot, "--cmd", "true"}, io.Discard); err == nil || err.Error() != "binding fail" {
		t.Fatalf("expected connect binding failure, got %v", err)
	}
	resolveBindingViewAppFn = origResolveBinding
	if err := appConnectCommand(context.Background(), []string{"myapp", "--project-root", projectRoot, "--cmd", "true", "--env", "OPENAI_API_KEY=BROKEN_FILE"}, io.Discard); err == nil || !strings.Contains(err.Error(), "env delivery requires kv secret") {
		t.Fatalf("expected env kind failure, got %v", err)
	}
	if err := appConnectCommand(context.Background(), []string{"myapp", "--project-root", projectRoot, "--cmd", "true", "--dotenv", "DATABASE_URL=BROKEN_FILE", "--dotenv-env", "ENV_FILE"}, io.Discard); err == nil || !strings.Contains(err.Error(), "temp dotenv delivery requires kv secret") {
		t.Fatalf("expected dotenv kind failure, got %v", err)
	}
	appResolvePathsFn = func() (paths.Paths, error) { return paths.Paths{}, errors.New("paths fail") }
	if err := appConnectCommand(context.Background(), []string{"myapp", "--project-root", projectRoot, "--cmd", "true", "--env", "OPENAI_API_KEY=API_TOKEN", "--install"}, io.Discard); err == nil || err.Error() != "paths fail" {
		t.Fatalf("expected launcher path failure, got %v", err)
	}
	appResolvePathsFn = origResolvePaths
	appMkdirAllFn = func(string, os.FileMode) error { return errors.New("mkdir fail") }
	if _, err := installAppLauncher("myapp"); err == nil || err.Error() != "mkdir fail" {
		t.Fatalf("expected launcher mkdir failure, got %v", err)
	}
	appMkdirAllFn = origMkdir
	appWriteFileFn = func(string, []byte, os.FileMode) error { return errors.New("write fail") }
	if _, err := installAppLauncher("myapp"); err == nil || err.Error() != "write fail" {
		t.Fatalf("expected launcher write failure, got %v", err)
	}
	appWriteFileFn = origWriteFile
	storeUpsertAppFn = func(*store.Handle, store.AppConsumer) (store.AppConsumer, error) {
		return store.AppConsumer{}, errors.New("upsert consumer fail")
	}
	if err := appConnectCommand(context.Background(), []string{"myapp", "--project-root", projectRoot, "--cmd", "true", "--env", "OPENAI_API_KEY=API_TOKEN"}, io.Discard); err == nil || err.Error() != "upsert consumer fail" {
		t.Fatalf("expected connect consumer upsert failure, got %v", err)
	}
	storeUpsertAppFn = origUpsertApp

	if err := appRunCommand(context.Background(), []string{}, io.Discard, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected run usage failure")
	}
	storeGetAppFn = func(*store.Handle, string) (store.AppConsumer, error) {
		return store.AppConsumer{}, errors.New("get consumer fail")
	}
	if err := appRunCommand(context.Background(), []string{"myapp"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || err.Error() != "get consumer fail" {
		t.Fatalf("expected run get consumer failure, got %v", err)
	}
	storeGetAppFn = origGetApp
	storeGetAppFn = func(*store.Handle, string) (store.AppConsumer, error) {
		return store.AppConsumer{Name: "myapp", ProjectRoot: projectRoot, Command: []string{"true"}}, nil
	}
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{}, errors.New("session fail")
	}
	if err := appRunCommand(context.Background(), []string{"myapp"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || err.Error() != "session fail" {
		t.Fatalf("expected run execution failure, got %v", err)
	}
	storeGetAppFn = origGetApp
	ensureSessionAppFn = origEnsureSession

	if err := appShellCommand(context.Background(), []string{}, io.Discard, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected shell usage failure")
	}
	storeGetAppFn = func(*store.Handle, string) (store.AppConsumer, error) {
		return store.AppConsumer{}, errors.New("get shell consumer fail")
	}
	if err := appShellCommand(context.Background(), []string{"myapp"}, io.Discard, io.Discard, &fakeStarter{}); err == nil || err.Error() != "get shell consumer fail" {
		t.Fatalf("expected shell get consumer failure, got %v", err)
	}
	storeGetAppFn = origGetApp

	if err := appInstallCommand(context.Background(), []string{}, io.Discard); err == nil {
		t.Fatal("expected install usage failure")
	}
	storeGetAppFn = func(*store.Handle, string) (store.AppConsumer, error) {
		return store.AppConsumer{}, errors.New("get install consumer fail")
	}
	if err := appInstallCommand(context.Background(), []string{"myapp"}, io.Discard); err == nil || err.Error() != "get install consumer fail" {
		t.Fatalf("expected install get consumer failure, got %v", err)
	}
	storeGetAppFn = origGetApp
	storeGetAppFn = func(*store.Handle, string) (store.AppConsumer, error) {
		return store.AppConsumer{Name: "myapp"}, nil
	}
	storeUpsertAppFn = func(*store.Handle, store.AppConsumer) (store.AppConsumer, error) {
		return store.AppConsumer{}, errors.New("install upsert fail")
	}
	if err := appInstallCommand(context.Background(), []string{"myapp"}, io.Discard); err == nil || err.Error() != "install upsert fail" {
		t.Fatalf("expected install consumer upsert failure, got %v", err)
	}
	storeUpsertAppFn = origUpsertApp
	storeGetAppFn = origGetApp

	if err := appDisconnectCommand(context.Background(), []string{}, io.Discard); err == nil {
		t.Fatal("expected disconnect usage failure")
	}
	storeGetAppFn = func(*store.Handle, string) (store.AppConsumer, error) {
		return store.AppConsumer{}, errors.New("get disconnect consumer fail")
	}
	if err := appDisconnectCommand(context.Background(), []string{"myapp"}, io.Discard); err == nil || err.Error() != "get disconnect consumer fail" {
		t.Fatalf("expected disconnect get consumer failure, got %v", err)
	}
	storeGetAppFn = origGetApp
	storeGetAppFn = func(*store.Handle, string) (store.AppConsumer, error) {
		return store.AppConsumer{Name: "myapp", LauncherPath: filepath.Join(t.TempDir(), "launcher"), Command: []string{"true"}}, nil
	}
	storeDeleteAppFn = func(*store.Handle, string) error { return nil }
	storeUpsertAppFn = func(_ *store.Handle, consumer store.AppConsumer) (store.AppConsumer, error) { return consumer, nil }
	appRemoveFn = func(string) error { return errors.New("remove fail") }
	if err := appDisconnectCommand(context.Background(), []string{"myapp"}, io.Discard); err == nil || err.Error() != "remove fail" {
		t.Fatalf("expected disconnect launcher removal failure, got %v", err)
	}
	appRemoveFn = os.Remove
	storeDeleteAppFn = origDeleteApp
	storeUpsertAppFn = origUpsertApp
	storeDeleteAppFn = func(*store.Handle, string) error { return errors.New("delete consumer fail") }
	if err := appDisconnectCommand(context.Background(), []string{"myapp"}, io.Discard); err == nil || err.Error() != "delete consumer fail" {
		t.Fatalf("expected disconnect consumer delete failure, got %v", err)
	}
	storeDeleteAppFn = origDeleteApp
	storeGetAppFn = origGetApp

	if err := appListCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected list parse failure")
	}
	storeListAppsFn = func(*store.Handle) []store.AppConsumer { return []store.AppConsumer{{Name: "myapp"}} }
	var listOut bytes.Buffer
	if err := appListCommand(context.Background(), nil, &listOut); err != nil || !strings.Contains(listOut.String(), "myapp") {
		t.Fatalf("expected list success, got %q err=%v", listOut.String(), err)
	}
}

func TestAgentConsumerErrorBranches(t *testing.T) {
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
	origStoreList := storeListAgentsFn
	origStoreUpsert := storeUpsertAgentFn
	origStoreDelete := storeDeleteAgentFn
	defer func() {
		openVaultHandleFn = origOpen
		appResolvePathsFn = origResolvePaths
		setupWriteAgentConfigsFn = origWriteAgents
		storeGetAgentFn = origStoreGet
		storeListAgentsFn = origStoreList
		storeUpsertAgentFn = origStoreUpsert
		storeDeleteAgentFn = origStoreDelete
	}()

	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault fail") }
	if err := agentConnectCommand(context.Background(), []string{"claude-code"}, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected agent connect open failure, got %v", err)
	}
	if err := agentDisconnectCommand(context.Background(), []string{"claude-code"}, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected agent disconnect open failure, got %v", err)
	}
	if err := agentListCommand(context.Background(), nil, io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected agent list open failure, got %v", err)
	}
	openVaultHandleFn = origOpen

	if err := agentConnectCommand(context.Background(), nil, io.Discard); err == nil {
		t.Fatal("expected agent connect usage failure")
	}
	if err := agentConnectCommand(context.Background(), []string{"unknown-agent"}, io.Discard); err == nil {
		t.Fatal("expected unsupported agent failure")
	}
	appResolvePathsFn = func() (paths.Paths, error) { return paths.Paths{}, errors.New("paths fail") }
	if err := agentConnectCommand(context.Background(), []string{"claude-code", "--project-root", projectRoot}, io.Discard); err == nil || err.Error() != "paths fail" {
		t.Fatalf("expected agent connect paths failure, got %v", err)
	}
	appResolvePathsFn = origResolvePaths
	setupWriteAgentConfigsFn = func([]setupAgentSpec, string) ([]setupAgentOutcome, error) {
		return nil, errors.New("write agent config fail")
	}
	if err := agentConnectCommand(context.Background(), []string{"claude-code", "--project-root", projectRoot}, io.Discard); err == nil || err.Error() != "write agent config fail" {
		t.Fatalf("expected agent config write failure, got %v", err)
	}
	setupWriteAgentConfigsFn = origWriteAgents
	storeUpsertAgentFn = func(*store.Handle, store.AgentConsumer) (store.AgentConsumer, error) {
		return store.AgentConsumer{}, errors.New("upsert agent fail")
	}
	if err := agentConnectCommand(context.Background(), []string{"claude-code", "--project-root", projectRoot}, io.Discard); err == nil || err.Error() != "upsert agent fail" {
		t.Fatalf("expected agent consumer upsert failure, got %v", err)
	}
	storeUpsertAgentFn = origStoreUpsert

	if err := agentDisconnectCommand(context.Background(), nil, io.Discard); err == nil {
		t.Fatal("expected agent disconnect usage failure")
	}
	storeGetAgentFn = func(*store.Handle, string) (store.AgentConsumer, error) {
		return store.AgentConsumer{}, errors.New("get agent fail")
	}
	if err := agentDisconnectCommand(context.Background(), []string{"claude-code"}, io.Discard); err == nil || err.Error() != "get agent fail" {
		t.Fatalf("expected disconnect get failure, got %v", err)
	}
	storeGetAgentFn = origStoreGet
	storeGetAgentFn = func(*store.Handle, string) (store.AgentConsumer, error) {
		return store.AgentConsumer{Name: "claude-code", AgentID: "unknown", ConfigPath: "/tmp/config"}, nil
	}
	if err := agentDisconnectCommand(context.Background(), []string{"claude-code"}, io.Discard); err == nil {
		t.Fatal("expected disconnect unsupported agent failure")
	}
	storeGetAgentFn = origStoreGet
	storeGetAgentFn = func(*store.Handle, string) (store.AgentConsumer, error) {
		return store.AgentConsumer{Name: "claude-code", AgentID: "claude-code", ConfigPath: filepath.Join(t.TempDir(), "missing.json")}, nil
	}
	if err := agentDisconnectCommand(context.Background(), []string{"claude-code"}, io.Discard); err == nil {
		t.Fatal("expected disconnect config read failure")
	}
	storeGetAgentFn = origStoreGet
	storeGetAgentFn = func(*store.Handle, string) (store.AgentConsumer, error) {
		return store.AgentConsumer{Name: "claude-code", AgentID: "claude-code", ConfigPath: filepath.Join(homeDir, ".claude.json")}, nil
	}
	storeDeleteAgentFn = func(*store.Handle, string) error { return errors.New("delete agent fail") }
	if err := agentDisconnectCommand(context.Background(), []string{"claude-code"}, io.Discard); err == nil || err.Error() != "delete agent fail" {
		t.Fatalf("expected disconnect delete failure, got %v", err)
	}
	storeDeleteAgentFn = origStoreDelete
	storeGetAgentFn = origStoreGet

	if err := agentListCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected agent list parse failure")
	}
	storeListAgentsFn = func(*store.Handle) []store.AgentConsumer { return []store.AgentConsumer{{Name: "claude-code"}} }
	var listOut bytes.Buffer
	if err := agentListCommand(context.Background(), nil, &listOut); err != nil || !strings.Contains(listOut.String(), "claude-code") {
		t.Fatalf("expected agent list success, got %q err=%v", listOut.String(), err)
	}
}
