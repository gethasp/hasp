package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestAgentConsumerLifecycle(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HOME", homeDir)
	t.Setenv("HASP_HOME", filepath.Join(homeDir, ".hasp"))
	t.Setenv("HASP_SOCKET", filepath.Join(t.TempDir(), "agent-shell.sock"))
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	var connectOut bytes.Buffer
	if err := Run(context.Background(), []string{"agent", "connect", "claude-code", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), &connectOut, &connectOut); err != nil {
		t.Fatalf("agent connect: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(connectOut.Bytes(), &payload); err != nil {
		t.Fatalf("decode agent connect output: %v", err)
	}
	config := payload["config"].(map[string]any)
	configPath := config["config_path"].(string)
	if configPath == "" {
		t.Fatal("expected config path in agent connect output")
	}
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read connected config: %v", err)
	}
	if !strings.Contains(string(configData), "\"hasp\"") || !strings.Contains(string(configData), "hasp-agent-claude-code") || strings.Contains(string(configData), "API_TOKEN") {
		t.Fatalf("unexpected agent config contents: %s", string(configData))
	}

	var listOut bytes.Buffer
	if err := Run(context.Background(), []string{"agent", "list", "--json"}, bytes.NewBuffer(nil), &listOut, &listOut); err != nil {
		t.Fatalf("agent list: %v", err)
	}
	if !strings.Contains(listOut.String(), "\"claude-code\"") {
		t.Fatalf("expected claude-code in agent list output, got %q", listOut.String())
	}

	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault handle: %v", err)
	}
	consumer, err := handle.GetAgentConsumer("claude-code")
	if err != nil {
		t.Fatalf("get agent consumer: %v", err)
	}
	if consumer.ProjectRoot == "" {
		t.Fatal("expected stored project root on agent consumer")
	}

	var disconnectOut bytes.Buffer
	if err := Run(context.Background(), []string{"agent", "disconnect", "claude-code"}, bytes.NewBuffer(nil), &disconnectOut, &disconnectOut); err != nil {
		t.Fatalf("agent disconnect: %v", err)
	}
	handle, err = openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("reopen vault handle: %v", err)
	}
	if _, err := handle.GetAgentConsumer("claude-code"); !errors.Is(err, store.ErrConsumerNotFound) {
		t.Fatalf("expected consumer removal after disconnect, got %v", err)
	}
	updatedConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read disconnected config: %v", err)
	}
	if strings.Contains(string(updatedConfig), "\"hasp\"") {
		t.Fatalf("expected HASP config stanza removed, got %s", string(updatedConfig))
	}
}

func TestAgentConsumerConnectWithoutProjectRoot(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("HASP_HOME", filepath.Join(homeDir, ".hasp"))
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	var connectOut bytes.Buffer
	if err := Run(context.Background(), []string{"agent", "connect", "codex-cli", "--json"}, bytes.NewBuffer(nil), &connectOut, &connectOut); err != nil {
		t.Fatalf("agent connect without project root: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(connectOut.Bytes(), &payload); err != nil {
		t.Fatalf("decode agent connect output: %v", err)
	}
	consumer := payload["consumer"].(map[string]any)
	if consumer["project_root"] != nil {
		t.Fatalf("expected omitted project root, got %#v", consumer["project_root"])
	}

	config := payload["config"].(map[string]any)
	configPath := config["config_path"].(string)
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read connected config: %v", err)
	}
	if !strings.Contains(string(configData), "[mcp_servers.hasp]") || !strings.Contains(string(configData), "hasp-agent-codex-cli") {
		t.Fatalf("expected codex config stanza, got %s", string(configData))
	}

	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault handle: %v", err)
	}
	stored, err := handle.GetAgentConsumer("codex-cli")
	if err != nil {
		t.Fatalf("get agent consumer: %v", err)
	}
	if stored.ProjectRoot != "" {
		t.Fatalf("expected empty stored project root, got %q", stored.ProjectRoot)
	}
}

func TestAgentShellPropagatesAgentSafeEnv(t *testing.T) {
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
	if err := Run(context.Background(), []string{"agent", "connect", "codex-cli", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("agent connect: %v", err)
	}

	shellScript := filepath.Join(t.TempDir(), "agent-shell.sh")
	if err := os.WriteFile(shellScript, []byte("#!/usr/bin/env bash\narg=\"$1\"\nif [ \"$arg\" = \"-l\" ]; then\n  shift\nfi\nprintf '%s|%s|%s|%s|%s' \"$HASP_AGENT_SAFE_MODE\" \"$HASP_SESSION_TOKEN\" \"$HASP_AGENT_CONSUMER\" \"$HASP_AGENT_PROJECT_ROOT\" \"$PWD\"\n"), 0o755); err != nil {
		t.Fatalf("write shell script: %v", err)
	}
	origShell := agentUserShellFn
	origStarter := agentNewStarterFn
	testStarter := newDaemonTestStarter(t)
	defer func() {
		agentUserShellFn = origShell
		agentNewStarterFn = origStarter
	}()
	agentUserShellFn = func() string { return shellScript }
	agentNewStarterFn = func() (starter, error) { return testStarter, nil }

	var shellOut bytes.Buffer
	if err := agentLaunchCommand(context.Background(), []string{"codex-cli"}, bytes.NewBuffer(nil), &shellOut, &shellOut, true); err != nil {
		t.Fatalf("agent shell: %v", err)
	}
	parts := strings.Split(shellOut.String(), "|")
	if len(parts) != 5 || parts[0] != "1" || parts[1] == "" || parts[2] != "codex-cli" || parts[3] == "" || parts[4] == "" {
		t.Fatalf("expected propagated agent-safe env, got %q", shellOut.String())
	}
}

func TestAgentMCPCommandServesToolsAndRegistersParent(t *testing.T) {
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
	if err := Run(context.Background(), []string{"agent", "connect", "claude-code", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("agent connect: %v", err)
	}

	origStarter := agentNewStarterFn
	testStarter := newDaemonTestStarter(t)
	defer func() { agentNewStarterFn = origStarter }()
	agentNewStarterFn = func() (starter, error) { return testStarter, nil }

	var input bytes.Buffer
	input.WriteString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n")
	var output bytes.Buffer
	if err := agentMCPCommand(context.Background(), []string{"claude-code"}, &input, &output); err != nil {
		t.Fatalf("agent mcp: %v", err)
	}
	if !strings.Contains(output.String(), "hasp_list") {
		t.Fatalf("expected mcp tools output, got %q", output.String())
	}
}

func TestAgentCommandHelperBranches(t *testing.T) {
	lockAppSeams(t)

	if value := envValue([]string{"A=1", "B=2"}, "B"); value != "2" {
		t.Fatalf("envValue = %q", value)
	}
	if value := envValue([]string{"A=1"}, "B"); value != "" {
		t.Fatalf("envValue missing = %q", value)
	}

	if err := registerProtectedProcess(context.Background(), &fakeStarter{err: io.EOF}, "", 0); err != nil {
		t.Fatalf("registerProtectedProcess should ignore empty token/pid: %v", err)
	}
	if err := registerProtectedProcess(context.Background(), &fakeStarter{err: io.EOF}, "token", 123); err == nil {
		t.Fatal("expected registerProtectedProcess starter failure")
	}
	if err := agentConsumerCommand(context.Background(), []string{"mcp", "--help"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("agent mcp help: %v", err)
	}
}

func TestAgentLaunchCommandBranches(t *testing.T) {
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
	if err := Run(context.Background(), []string{"agent", "connect", "codex-cli", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("agent connect: %v", err)
	}

	if err := agentLaunchCommand(context.Background(), []string{"codex-cli"}, bytes.NewBuffer(nil), io.Discard, io.Discard, false); err == nil {
		t.Fatal("expected usage failure when no command is provided")
	}

	origStarter := agentNewStarterFn
	defer func() { agentNewStarterFn = origStarter }()
	agentNewStarterFn = func() (starter, error) { return &fakeStarter{err: io.EOF}, nil }
	if err := agentLaunchCommand(context.Background(), []string{"codex-cli", "--", "true"}, bytes.NewBuffer(nil), io.Discard, io.Discard, false); err == nil {
		t.Fatal("expected startup failure from fake starter")
	}
}

func TestAgentLaunchFallbackConsumerAndCommandErrors(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HOME", homeDir)
	t.Setenv("HASP_HOME", filepath.Join(homeDir, ".hasp"))
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	t.Setenv(envAgentProjectRoot, projectRoot)

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault handle: %v", err)
	}
	if _, _, _, err := ensureProjectBindingExplicit(context.Background(), handle, projectRoot); err != nil {
		t.Fatalf("ensure project binding: %v", err)
	}

	origGet := storeGetAgentFn
	origStarter := agentNewStarterFn
	origExec := agentExecCommandContextFn
	defer func() {
		storeGetAgentFn = origGet
		agentNewStarterFn = origStarter
		agentExecCommandContextFn = origExec
	}()

	storeGetAgentFn = func(*store.Handle, string) (store.AgentConsumer, error) {
		return store.AgentConsumer{}, store.ErrConsumerNotFound
	}
	agentNewStarterFn = func() (starter, error) { return newDaemonTestStarter(t), nil }
	if err := agentLaunchCommand(context.Background(), []string{"ghost", "--", "sh", "-c", "exit 0"}, bytes.NewBuffer(nil), io.Discard, io.Discard, false); err != nil {
		t.Fatalf("expected fallback consumer launch to succeed: %v", err)
	}

	agentExecCommandContextFn = func(context.Context, string, ...string) *exec.Cmd {
		return exec.Command("/definitely-missing-binary")
	}
	if err := agentLaunchCommand(context.Background(), []string{"ghost", "--", "missing"}, bytes.NewBuffer(nil), io.Discard, io.Discard, false); err == nil {
		t.Fatal("expected command start failure")
	}
}

func TestAgentCommandAndEnvBuilderBranches(t *testing.T) {
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
	if err := Run(context.Background(), []string{"agent", "connect", "claude-code", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("agent connect: %v", err)
	}

	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	consumer, err := handle.GetAgentConsumer("claude-code")
	if err != nil {
		t.Fatalf("get agent consumer: %v", err)
	}

	origPaths := appResolvePathsFn
	origStarter := agentNewStarterFn
	origGet := storeGetAgentFn
	origShell := agentUserShellFn
	origBuildEnv := agentBuildExecutionEnvFn
	origRegister := agentRegisterProcessFn
	origServe := agentServeMCPFn
	origOpenSession := agentOpenSessionFn
	defer func() {
		appResolvePathsFn = origPaths
		agentNewStarterFn = origStarter
		storeGetAgentFn = origGet
		agentUserShellFn = origShell
		agentBuildExecutionEnvFn = origBuildEnv
		agentRegisterProcessFn = origRegister
		agentServeMCPFn = origServe
		agentOpenSessionFn = origOpenSession
	}()

	testStarter := newDaemonTestStarter(t)
	agentNewStarterFn = func() (starter, error) { return testStarter, nil }
	if err := agentConsumerCommand(context.Background(), []string{"launch", "claude-code", "--", "true"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("agentConsumerCommand launch: %v", err)
	}
	shellScript := filepath.Join(t.TempDir(), "agent-shell-branch.sh")
	if err := os.WriteFile(shellScript, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write shell script: %v", err)
	}
	agentUserShellFn = func() string { return shellScript }
	if err := agentConsumerCommand(context.Background(), []string{"shell", "claude-code"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("agentConsumerCommand shell: %v", err)
	}
	if err := agentConsumerCommand(context.Background(), []string{"list"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("agentConsumerCommand list: %v", err)
	}

	appResolvePathsFn = func() (paths.Paths, error) { return paths.Paths{}, errors.New("paths fail") }
	if _, err := buildAgentExecutionEnv(context.Background(), handle, consumer, testStarter, "agent:"+consumer.Name); err == nil || err.Error() != "paths fail" {
		t.Fatalf("expected buildAgentExecutionEnv paths failure, got %v", err)
	}
	appResolvePathsFn = origPaths

	if _, err := buildAgentExecutionEnv(context.Background(), handle, store.AgentConsumer{Name: "claude-code", AgentID: "claude-code"}, testStarter, "agent:claude-code"); err != nil {
		t.Fatalf("buildAgentExecutionEnv no project root: %v", err)
	}
	agentOpenSessionFn = func(context.Context, *runtime.Client, string, store.AgentConsumer) (runtime.OpenSessionResponse, error) {
		return runtime.OpenSessionResponse{}, errors.New("open session fail")
	}
	if _, err := buildAgentExecutionEnv(context.Background(), handle, store.AgentConsumer{Name: "claude-code", AgentID: "claude-code"}, testStarter, "agent:claude-code"); err == nil || err.Error() != "open session fail" {
		t.Fatalf("expected buildAgentExecutionEnv open session failure, got %v", err)
	}
	agentOpenSessionFn = origOpenSession

	storeGetAgentFn = func(*store.Handle, string) (store.AgentConsumer, error) {
		return store.AgentConsumer{}, errors.New("get fail")
	}
	if err := agentMCPCommand(context.Background(), []string{"claude-code"}, bytes.NewBufferString(""), io.Discard); err == nil || err.Error() != "get fail" {
		t.Fatalf("expected agentMCPCommand get failure, got %v", err)
	}

	agentBuildExecutionEnvFn = func(context.Context, *store.Handle, store.AgentConsumer, starter, string) ([]string, error) {
		return nil, errors.New("env fail")
	}
	storeGetAgentFn = origGet
	if err := agentLaunchCommand(context.Background(), []string{"claude-code", "--", "true"}, bytes.NewBuffer(nil), io.Discard, io.Discard, false); err == nil || err.Error() != "env fail" {
		t.Fatalf("expected launch env failure, got %v", err)
	}
	if err := agentMCPCommand(context.Background(), []string{"claude-code"}, bytes.NewBufferString(""), io.Discard); err == nil || err.Error() != "env fail" {
		t.Fatalf("expected mcp env failure, got %v", err)
	}

	origSetEnv := setupSetEnvFn
	defer func() { setupSetEnvFn = origSetEnv }()
	agentBuildExecutionEnvFn = func(context.Context, *store.Handle, store.AgentConsumer, starter, string) ([]string, error) {
		return []string{envAgentSafeMode + "=1", envAgentConsumer + "=claude-code"}, nil
	}
	setupSetEnvFn = func(string, string) (func(), error) { return nil, errors.New("setenv fail") }
	if err := agentMCPCommand(context.Background(), []string{"claude-code"}, bytes.NewBufferString(""), io.Discard); err == nil || err.Error() != "setenv fail" {
		t.Fatalf("expected mcp setenv failure, got %v", err)
	}
	setupSetEnvFn = origSetEnv

	agentBuildExecutionEnvFn = func(context.Context, *store.Handle, store.AgentConsumer, starter, string) ([]string, error) {
		return []string{envAgentSafeMode + "=1", envAgentConsumer + "=claude-code", envSessionToken + "=token"}, nil
	}
	agentRegisterProcessFn = func(context.Context, starter, string, int) error { return errors.New("register fail") }
	if err := agentMCPCommand(context.Background(), []string{"claude-code"}, bytes.NewBufferString(""), io.Discard); err == nil || err.Error() != "register fail" {
		t.Fatalf("expected mcp register failure, got %v", err)
	}
	agentRegisterProcessFn = origRegister
	agentBuildExecutionEnvFn = func(context.Context, *store.Handle, store.AgentConsumer, starter, string) ([]string, error) {
		return []string{envAgentSafeMode + "=1", envAgentConsumer + "=claude-code"}, nil
	}
	agentServeMCPFn = func(context.Context, io.Reader, io.Writer) error { return errors.New("serve fail") }
	if err := agentMCPCommand(context.Background(), []string{"claude-code"}, bytes.NewBufferString(""), io.Discard); err == nil || err.Error() != "serve fail" {
		t.Fatalf("expected mcp serve failure, got %v", err)
	}
	agentBuildExecutionEnvFn = func(context.Context, *store.Handle, store.AgentConsumer, starter, string) ([]string, error) {
		return []string{"BROKEN", envAgentSafeMode + "=1", envAgentConsumer + "=claude-code"}, nil
	}
	if err := agentMCPCommand(context.Background(), []string{"claude-code"}, bytes.NewBufferString(""), io.Discard); err == nil || err.Error() != "serve fail" {
		t.Fatalf("expected mcp malformed env entry branch, got %v", err)
	}
}

func TestAgentMCPAndWrapperInstallBranches(t *testing.T) {
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
	if err := Run(context.Background(), []string{"agent", "connect", "claude-code", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("agent connect: %v", err)
	}

	origOpen := openVaultHandleFn
	defer func() { openVaultHandleFn = origOpen }()
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault fail") }
	if err := agentMCPCommand(context.Background(), []string{"claude-code"}, bytes.NewBufferString(""), io.Discard); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected agentMCPCommand open failure, got %v", err)
	}
	openVaultHandleFn = origOpen

	if err := agentMCPCommand(context.Background(), nil, bytes.NewBuffer(nil), io.Discard); err == nil {
		t.Fatal("expected agentMCPCommand usage failure")
	}
	if err := agentMCPCommand(context.Background(), []string{"claude-code", "--bad"}, bytes.NewBuffer(nil), io.Discard); err == nil {
		t.Fatal("expected agentMCPCommand parse failure")
	}
	agentNewStarterFn = func() (starter, error) { return nil, errors.New("starter build fail") }
	if err := agentMCPCommand(context.Background(), []string{"claude-code"}, bytes.NewBufferString(""), io.Discard); err == nil || err.Error() != "starter build fail" {
		t.Fatalf("expected agentMCPCommand starter construction failure, got %v", err)
	}

	origStarter := agentNewStarterFn
	origPaths := appResolvePathsFn
	origRead := setupReadFileFn
	origWrite := setupWriteFileFn
	origMkdir := setupMkdirAllFn
	origSetEnv := setupSetEnvFn
	origServe := agentServeMCPFn
	origBuildEnv := agentBuildExecutionEnvFn
	defer func() {
		agentNewStarterFn = origStarter
		appResolvePathsFn = origPaths
		setupReadFileFn = origRead
		setupWriteFileFn = origWrite
		setupMkdirAllFn = origMkdir
		setupSetEnvFn = origSetEnv
		agentServeMCPFn = origServe
		agentBuildExecutionEnvFn = origBuildEnv
	}()

	agentNewStarterFn = func() (starter, error) { return &fakeStarter{err: io.EOF}, nil }
	if err := agentMCPCommand(context.Background(), []string{"claude-code"}, bytes.NewBufferString(""), io.Discard); err == nil {
		t.Fatal("expected agentMCPCommand starter failure")
	}

	agentNewStarterFn = func() (starter, error) { return newDaemonTestStarter(t), nil }
	appResolvePathsFn = func() (paths.Paths, error) { return paths.Paths{}, errors.New("paths fail") }
	if err := agentMCPCommand(context.Background(), []string{"claude-code"}, bytes.NewBufferString(""), io.Discard); err == nil || err.Error() != "paths fail" {
		t.Fatalf("expected agentMCPCommand env build failure, got %v", err)
	}
	appResolvePathsFn = origPaths

	setupSetEnvFn = func(string, string) (func(), error) { return nil, errors.New("setenv fail") }
	agentBuildExecutionEnvFn = func(context.Context, *store.Handle, store.AgentConsumer, starter, string) ([]string, error) {
		return []string{envAgentSafeMode + "=1", envAgentConsumer + "=claude-code"}, nil
	}
	if err := agentMCPCommand(context.Background(), []string{"claude-code"}, bytes.NewBufferString(""), io.Discard); err == nil || err.Error() != "setenv fail" {
		t.Fatalf("expected agentMCPCommand setenv failure, got %v", err)
	}
	setupSetEnvFn = origSetEnv
	agentBuildExecutionEnvFn = origBuildEnv

	if _, err := setupInstallAgentWrapper(filepath.Join(homeDir, ".hasp"), "/bin/hasp", ""); err == nil {
		t.Fatal("expected setupInstallAgentWrapper missing agent failure")
	}
	setupReadFileFn = func(string) ([]byte, error) { return nil, errors.New("read fail") }
	if _, err := setupInstallAgentWrapper(filepath.Join(homeDir, ".hasp"), "/bin/hasp", "cursor"); err == nil || err.Error() != "read fail" {
		t.Fatalf("expected wrapper read failure, got %v", err)
	}
	setupReadFileFn = origRead
	setupMkdirAllFn = func(string, os.FileMode) error { return errors.New("mkdir fail") }
	if _, err := setupInstallAgentWrapper(filepath.Join(homeDir, ".missing"), "/bin/hasp", "cursor"); err == nil || err.Error() != "mkdir fail" {
		t.Fatalf("expected wrapper mkdir failure, got %v", err)
	}
	setupMkdirAllFn = os.MkdirAll
	setupWriteFileFn = func(string, []byte, os.FileMode) error { return errors.New("write fail") }
	if _, err := setupInstallAgentWrapper(filepath.Join(homeDir, ".hasp"), "/bin/hasp", "cursor"); err == nil || err.Error() != "write fail" {
		t.Fatalf("expected wrapper write failure, got %v", err)
	}
	agentServeMCPFn = func(context.Context, io.Reader, io.Writer) error { return errors.New("serve fail") }
	if err := agentConsumerCommand(context.Background(), []string{"mcp", "claude-code"}, bytes.NewBufferString(""), io.Discard, io.Discard); err == nil || err.Error() != "serve fail" {
		t.Fatalf("expected agent consumer mcp route failure, got %v", err)
	}
	agentServeMCPFn = origServe
	agentBuildExecutionEnvFn = func(context.Context, *store.Handle, store.AgentConsumer, starter, string) ([]string, error) {
		return []string{envAgentSafeMode + "=1", envAgentConsumer + "=claude-code"}, nil
	}
	if err := agentMCPCommand(context.Background(), []string{"claude-code"}, bytes.NewBufferString(""), io.Discard); err != nil {
		t.Fatalf("expected mcp success without session token registration, got %v", err)
	}
}

func TestAgentBuilderAdditionalBranches(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("HASP_HOME", filepath.Join(homeDir, ".hasp"))
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, err := buildAgentExecutionEnv(context.Background(), handle, store.AgentConsumer{Name: "claude-code", ProjectRoot: "/definitely/missing/repo"}, &fakeStarter{err: io.EOF}, "agent:claude-code"); err == nil {
		t.Fatal("expected project binding/ensure client failure")
	}
	if _, err := setupWriteAgentConfigs(nil, filepath.Join(homeDir, ".hasp")); err != nil {
		t.Fatalf("expected empty agent config set to succeed: %v", err)
	}
}

func TestAgentLaunchOpenAndLookupFailures(t *testing.T) {
	lockAppSeams(t)

	origOpen := openVaultHandleFn
	origGet := storeGetAgentFn
	origStarter := agentNewStarterFn
	origShell := agentUserShellFn
	defer func() {
		openVaultHandleFn = origOpen
		storeGetAgentFn = origGet
		agentNewStarterFn = origStarter
		agentUserShellFn = origShell
	}()

	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault fail") }
	if err := agentLaunchCommand(context.Background(), []string{"claude-code", "--", "true"}, bytes.NewBuffer(nil), io.Discard, io.Discard, false); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected open vault failure, got %v", err)
	}

	// Stub openVaultHandleFn to succeed so the flow can reach storeGetAgentFn
	// and agentNewStarterFn. Relying on the real implementation here would
	// require an initialized vault on disk, which is not the case in a clean
	// CI environment.
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return &store.Handle{}, nil }
	storeGetAgentFn = func(*store.Handle, string) (store.AgentConsumer, error) {
		return store.AgentConsumer{}, errors.New("get fail")
	}
	if err := agentLaunchCommand(context.Background(), []string{"claude-code", "--", "true"}, bytes.NewBuffer(nil), io.Discard, io.Discard, false); err == nil || err.Error() != "get fail" {
		t.Fatalf("expected get agent failure, got %v", err)
	}

	storeGetAgentFn = origGet
	agentNewStarterFn = func() (starter, error) { return nil, errors.New("starter fail") }
	if err := agentLaunchCommand(context.Background(), []string{"claude-code", "--", "true"}, bytes.NewBuffer(nil), io.Discard, io.Discard, false); err == nil || err.Error() != "starter fail" {
		t.Fatalf("expected starter failure, got %v", err)
	}
}

func TestAgentLaunchAdditionalBranches(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HOME", homeDir)
	t.Setenv("HASP_HOME", filepath.Join(homeDir, ".hasp"))
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	t.Setenv(envAgentProjectRoot, projectRoot)

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"agent", "connect", "claude-code", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("agent connect: %v", err)
	}

	origStarter := agentNewStarterFn
	origShell := agentUserShellFn
	origRegister := agentRegisterProcessFn
	origBuildEnv := agentBuildExecutionEnvFn
	defer func() {
		agentNewStarterFn = origStarter
		agentUserShellFn = origShell
		agentRegisterProcessFn = origRegister
		agentBuildExecutionEnvFn = origBuildEnv
	}()
	testStarter := newDaemonTestStarter(t)
	agentNewStarterFn = func() (starter, error) { return testStarter, nil }

	if err := agentLaunchCommand(context.Background(), nil, bytes.NewBuffer(nil), io.Discard, io.Discard, false); err == nil {
		t.Fatal("expected blank launch usage failure")
	}
	if err := agentLaunchCommand(context.Background(), []string{""}, bytes.NewBuffer(nil), io.Discard, io.Discard, false); err == nil {
		t.Fatal("expected empty consumer name usage failure")
	}
	if err := agentLaunchCommand(context.Background(), []string{"--bad"}, bytes.NewBuffer(nil), io.Discard, io.Discard, false); err == nil {
		t.Fatal("expected launch parse failure")
	}
	if err := agentLaunchCommand(context.Background(), []string{"ghost", "--", "sh", "-c", "exit 7"}, bytes.NewBuffer(nil), io.Discard, io.Discard, false); err == nil || !strings.Contains(err.Error(), "code 7") {
		t.Fatalf("expected exit code branch, got %v", err)
	}
	defaultShell := filepath.Join(t.TempDir(), "shell-default.sh")
	if err := os.WriteFile(defaultShell, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write default shell: %v", err)
	}
	t.Setenv("SHELL", defaultShell)
	if err := agentLaunchCommand(context.Background(), []string{"ghost"}, bytes.NewBuffer(nil), io.Discard, io.Discard, true); err != nil {
		t.Fatalf("expected default agentUserShellFn to use SHELL env, got %v", err)
	}
	agentUserShellFn = func() string { return "" }
	if err := agentLaunchCommand(context.Background(), []string{"ghost", "--", "-c", "exit 0"}, bytes.NewBuffer(nil), io.Discard, io.Discard, true); err != nil {
		t.Fatalf("expected default shell fallback to succeed: %v", err)
	}
	agentBuildExecutionEnvFn = func(context.Context, *store.Handle, store.AgentConsumer, starter, string) ([]string, error) {
		return []string{envAgentSafeMode + "=1", envSessionToken + "=token"}, nil
	}
	agentRegisterProcessFn = func(context.Context, starter, string, int) error { return errors.New("register fail") }
	if err := agentLaunchCommand(context.Background(), []string{"ghost", "--", "sh", "-c", "exit 0"}, bytes.NewBuffer(nil), io.Discard, io.Discard, false); err == nil || err.Error() != "register fail" {
		t.Fatalf("expected register failure, got %v", err)
	}
	agentRegisterProcessFn = origRegister
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := agentLaunchCommand(cancelCtx, []string{"ghost", "--", "sh", "-c", "sleep 1"}, bytes.NewBuffer(nil), io.Discard, io.Discard, false); err == nil {
		t.Fatal("expected non-exit wait error from canceled context")
	}
	origExec := agentExecCommandContextFn
	defer func() { agentExecCommandContextFn = origExec }()
	agentBuildExecutionEnvFn = func(context.Context, *store.Handle, store.AgentConsumer, starter, string) ([]string, error) {
		return []string{envAgentSafeMode + "=1"}, nil
	}
	agentExecCommandContextFn = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf x")
	}
	waitErr := errWriter{err: errors.New("wait fail")}
	if err := agentLaunchCommand(context.Background(), []string{"ghost", "--", "ignored"}, bytes.NewBuffer(nil), waitErr, io.Discard, false); err == nil || !strings.Contains(err.Error(), "wait fail") {
		t.Fatalf("expected raw wait failure branch, got %v", err)
	}
}
