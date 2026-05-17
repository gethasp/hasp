package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/profiles"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestSetupCommandConfiguresAgentsAndMCPHarness(t *testing.T) {
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
	if err := runWithStarter(
		context.Background(),
		[]string{
			"setup",
			"--non-interactive",
			"--hasp-home", haspHome,
			"--repo", repo,
			"--agent", "claude-code",
			"--agent", "cursor",
			"--master-password-env", "SETUP_MASTER_PASSWORD",
			"--install-hooks=false",
			"--enable-convenience-unlock=false",
			"--overwrite-existing-config=true",
		},
		bytes.NewBuffer(nil),
		&stdout,
		io.Discard,
		&fakeStarter{},
	); err != nil {
		t.Fatalf("setup command: %v", err)
	}

	var summary setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode setup summary: %v", err)
	}
	if summary.InitState != "created" {
		t.Fatalf("unexpected init state: %+v", summary)
	}
	if summary.Binding == nil || summary.Binding.CanonicalRoot == "" {
		t.Fatalf("expected repo binding in summary: %+v", summary)
	}
	if len(summary.Agents) != 2 {
		t.Fatalf("expected agent outcomes, got %+v", summary.Agents)
	}
	t.Setenv("HASP_HOME", haspHome)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault after setup: %v", err)
	}
	agents := handle.ListAgentConsumers()
	if len(agents) != 2 {
		t.Fatalf("expected setup to persist agent consumers, got %+v", agents)
	}
	for _, agent := range agents {
		if agent.ProjectRoot != summary.Binding.CanonicalRoot || agent.ConfigPath == "" {
			t.Fatalf("setup persisted incomplete agent consumer: %+v", agent)
		}
	}

	statePath := filepath.Join(haspHome, "vault.json.enc")
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("stat vault state: %v", err)
	}
	claudeConfig := filepath.Join(userHome, ".claude.json")
	cursorConfig := filepath.Join(userHome, ".cursor", "mcp.json")
	for _, path := range []string{claudeConfig, cursorConfig} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(data)
		if strings.Contains(text, "correct horse battery staple") {
			t.Fatalf("config leaked master password: %s", text)
		}
		if !strings.Contains(text, "\"command\": ") || !strings.Contains(text, "hasp-agent-") {
			t.Fatalf("config missing hasp MCP command: %s", text)
		}
	}

	var mcpOut bytes.Buffer
	if err := runWithStarter(
		context.Background(),
		[]string{"mcp"},
		bytes.NewBufferString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n"),
		&mcpOut,
		io.Discard,
		&fakeStarter{},
	); err != nil {
		t.Fatalf("mcp serve tools/list: %v", err)
	}
	if !strings.Contains(mcpOut.String(), "hasp_list") {
		t.Fatalf("expected MCP tools list, got %s", mcpOut.String())
	}

	stdout.Reset()
	if err := runWithStarter(
		context.Background(),
		[]string{
			"setup",
			"--non-interactive",
			"--hasp-home", haspHome,
			"--repo", repo,
			"--agent", "claude-code",
			"--agent", "cursor",
			"--master-password-env", "SETUP_MASTER_PASSWORD",
			"--install-hooks=false",
			"--enable-convenience-unlock=false",
			"--overwrite-existing-config=true",
		},
		bytes.NewBuffer(nil),
		&stdout,
		io.Discard,
		&fakeStarter{},
	); err != nil {
		t.Fatalf("rerun setup command: %v", err)
	}
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode rerun setup summary: %v", err)
	}
	for _, agent := range summary.Agents {
		if agent.Changed {
			t.Fatalf("expected idempotent config write, got %+v", summary.Agents)
		}
	}
}

func TestSetupCommandPersistsAndVerifiesEverySupportedAgentHarness(t *testing.T) {
	lockAppSeams(t)
	userHome := t.TempDir()
	haspHome := filepath.Join(t.TempDir(), "hasp-home")
	repo := t.TempDir()
	t.Setenv("HOME", userHome)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(userHome, ".config"))
	t.Setenv("SETUP_MASTER_PASSWORD", "correct horse battery staple")

	origHome := setupUserHomeDirFn
	origLookPath := setupLookPathFn
	origExecutable := setupExecutableFn
	origNewStarter := agentNewStarterFn
	origBuildEnv := agentBuildExecutionEnvFn
	origRegister := agentRegisterProcessFn
	defer func() {
		setupUserHomeDirFn = origHome
		setupLookPathFn = origLookPath
		setupExecutableFn = origExecutable
		agentNewStarterFn = origNewStarter
		agentBuildExecutionEnvFn = origBuildEnv
		agentRegisterProcessFn = origRegister
	}()
	setupUserHomeDirFn = func() (string, error) { return userHome, nil }
	setupLookPathFn = func(name string) (string, error) {
		if name == "hasp" {
			return "/opt/homebrew/bin/hasp", nil
		}
		return "", os.ErrNotExist
	}
	setupExecutableFn = func() (string, error) { return "/opt/homebrew/bin/hasp", nil }
	agentNewStarterFn = func() (starter, error) { return &fakeStarter{}, nil }

	builtConsumers := map[string]store.AgentConsumer{}
	agentBuildExecutionEnvFn = func(_ context.Context, _ *store.Handle, consumer store.AgentConsumer, _ starter, _ string) ([]string, error) {
		builtConsumers[consumer.Name] = consumer
		return []string{secrettypes.EnvSessionToken + "=token-" + consumer.Name}, nil
	}
	agentRegisterProcessFn = func(context.Context, starter, string, int) error { return nil }

	supported := setupSupportedAgents()
	args := []string{
		"setup",
		"--non-interactive",
		"--hasp-home", haspHome,
		"--repo", repo,
		"--master-password-env", "SETUP_MASTER_PASSWORD",
		"--install-hooks=false",
		"--enable-convenience-unlock=false",
		"--overwrite-existing-config=true",
	}
	for _, agent := range supported {
		args = append(args, "--agent", agent.ID)
	}

	var stdout bytes.Buffer
	if err := runWithStarter(context.Background(), args, bytes.NewBuffer(nil), &stdout, io.Discard, &fakeStarter{}); err != nil {
		t.Fatalf("setup all supported agents: %v", err)
	}
	var summary setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode setup summary: %v", err)
	}
	if len(summary.Agents) != len(supported) {
		t.Fatalf("expected all supported agent outcomes, got %+v", summary.Agents)
	}
	if summary.Binding == nil || summary.Binding.CanonicalRoot == "" {
		t.Fatalf("expected setup binding, got %+v", summary.Binding)
	}

	t.Setenv("HASP_HOME", haspHome)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault after setup: %v", err)
	}
	consumersByName := map[string]store.AgentConsumer{}
	for _, consumer := range handle.ListAgentConsumers() {
		consumersByName[consumer.Name] = consumer
	}

	for _, agent := range supported {
		t.Run(agent.ID, func(t *testing.T) {
			wrapperPath, err := setupAgentWrapperPath(haspHome, agent.ID)
			if err != nil {
				t.Fatalf("wrapper path: %v", err)
			}
			consumer, ok := consumersByName[agent.ID]
			if !ok {
				t.Fatalf("missing persisted agent consumer for %s; got %+v", agent.ID, consumersByName)
			}
			wantConfigPath := agent.ConfigPath("")
			if agent.Format == "manual" {
				wantConfigPath = wrapperPath
			}
			if consumer.AgentID != agent.ID || consumer.ProjectRoot != summary.Binding.CanonicalRoot || consumer.ConfigPath != wantConfigPath {
				t.Fatalf("unexpected persisted consumer for %s: %+v want config %q root %q", agent.ID, consumer, wantConfigPath, summary.Binding.CanonicalRoot)
			}

			wrapperBytes, err := os.ReadFile(wrapperPath)
			if err != nil {
				t.Fatalf("read wrapper for %s: %v", agent.ID, err)
			}
			wrapper := string(wrapperBytes)
			if !strings.Contains(wrapper, setupManagedAgentWrapperMarker) ||
				!strings.Contains(wrapper, "HASP_HOME="+strconvQuote(haspHome)) ||
				!strings.Contains(wrapper, " agent mcp "+strconvQuote(agent.ID)+" ") {
				t.Fatalf("wrapper for %s does not launch the managed agent MCP path:\n%s", agent.ID, wrapper)
			}

			if agent.Format != "manual" {
				configBytes, err := os.ReadFile(wantConfigPath)
				if err != nil {
					t.Fatalf("read config for %s: %v", agent.ID, err)
				}
				config := string(configBytes)
				if agent.Format == "pi-package" {
					if !strings.Contains(config, setupPiPackagePath(haspHome)) {
						t.Fatalf("config for %s does not reference generated Pi package %s:\n%s", agent.ID, setupPiPackagePath(haspHome), config)
					}
					extensionBytes, err := os.ReadFile(filepath.Join(setupPiPackagePath(haspHome), "extensions", "hasp", "index.js"))
					if err != nil {
						t.Fatalf("read generated Pi extension for %s: %v", agent.ID, err)
					}
					if !strings.Contains(string(extensionBytes), wrapperPath) {
						t.Fatalf("generated Pi extension for %s does not reference wrapper %s:\n%s", agent.ID, wrapperPath, string(extensionBytes))
					}
				} else if !strings.Contains(config, wrapperPath) {
					t.Fatalf("config for %s does not reference wrapper %s:\n%s", agent.ID, wrapperPath, config)
				}
				if strings.Contains(config, "correct horse battery staple") {
					t.Fatalf("config for %s leaked the setup password:\n%s", agent.ID, config)
				}
			}

			var mcpOut bytes.Buffer
			request := strings.Join([]string{
				`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"hasp-test","version":"0"}}}`,
				`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
				"",
			}, "\n")
			if err := agentMCPCommand(context.Background(), []string{agent.ID}, bytes.NewBufferString(request), &mcpOut); err != nil {
				t.Fatalf("agent mcp %s: %v", agent.ID, err)
			}
			if !strings.Contains(mcpOut.String(), `"protocolVersion"`) || !strings.Contains(mcpOut.String(), "hasp_list") {
				t.Fatalf("agent mcp %s did not complete initialize + tools/list: %s", agent.ID, mcpOut.String())
			}
			built, ok := builtConsumers[agent.ID]
			if !ok || built.ConfigPath != wantConfigPath || built.ProjectRoot != summary.Binding.CanonicalRoot {
				t.Fatalf("agent mcp %s built env with wrong consumer: %+v", agent.ID, built)
			}
		})
	}
}

func TestSetupSupportedAgentHarnessesStayInReleaseCatalog(t *testing.T) {
	supported := setupSupportedAgents()
	catalog, err := profiles.LoadCatalog()
	if err != nil {
		t.Fatalf("load profile catalog: %v", err)
	}
	profilesByID := map[string]profiles.Profile{}
	for _, profile := range catalog {
		profilesByID[profile.ID] = profile
	}

	for _, agent := range supported {
		profile, ok := profilesByID[agent.ID]
		if !ok {
			t.Fatalf("supported setup agent %s is missing from the shipped profile catalog", agent.ID)
		}
		expectedCommand := []string{"hasp", "agent", "mcp", agent.ID}
		if !slices.Equal(profile.Command, expectedCommand) {
			t.Fatalf("profile %s command = %v, want %v", agent.ID, profile.Command, expectedCommand)
		}
		gate, err := profiles.ReleaseGateForProfile(agent.ID)
		if err != nil {
			t.Fatalf("release gate for %s: %v", agent.ID, err)
		}
		if !slices.Contains(gate.EvalTests, "TestMCPEndToEndEval") ||
			!slices.Contains(gate.EvalTests, "TestProfileReleaseGateEval") ||
			len(gate.Benchmarks) == 0 {
			t.Fatalf("release gate for %s does not cover MCP/profile evals and benchmarks: %+v", agent.ID, gate)
		}
		if _, err := profiles.LoadRegressionFixture(profile); err != nil {
			t.Fatalf("load regression fixture for %s: %v", agent.ID, err)
		}
	}
}
