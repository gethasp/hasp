package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type memorySetupKeyring struct {
	values map[string]string
}

func (m *memorySetupKeyring) Set(_ context.Context, service string, account string, value string) error {
	if m.values == nil {
		m.values = map[string]string{}
	}
	m.values[service+":"+account] = value
	return nil
}

func (m *memorySetupKeyring) Get(service string, account string) (string, error) {
	if value, ok := m.values[service+":"+account]; ok {
		return value, nil
	}
	return "", store.KeyringItemNotFoundError{Err: store.ErrKeyringUnavailable}
}

func (m *memorySetupKeyring) Delete(service string, account string) error {
	delete(m.values, service+":"+account)
	return nil
}

func TestSetupCommandNonInteractiveFailsForProjectScopedOptionsWithoutRepo(t *testing.T) {
	lockAppSeams(t)
	harness := newSetupHarness(t)
	t.Setenv("SETUP_MASTER_PASSWORD", "correct horse battery staple")

	err := runWithStarter(
		context.Background(),
		[]string{
			"setup",
			"--non-interactive",
			"--hasp-home", filepath.Join(harness.userHome, "hasp-home"),
			"--master-password-env", "SETUP_MASTER_PASSWORD",
			"--agent", "claude-code",
			"--bind-imports",
			"--install-hooks=false",
			"--enable-convenience-unlock=false",
		},
		bytes.NewBuffer(nil),
		io.Discard,
		io.Discard,
		&fakeStarter{},
	)
	if err == nil || !strings.Contains(err.Error(), "project-scoped setup options require --project-root") {
		t.Fatalf("expected project-scoped setup options failure, got %v", err)
	}
}

func TestUpsertCodexMCPServerConfigReplacesExistingBlock(t *testing.T) {
	wrapperPath := "/tmp/hasp-home/bin/hasp-agent-codex-cli"
	updated := upsertCodexMCPServerConfig([]byte("model = \"gpt-5.4\"\n"), "/tmp/hasp-home", wrapperPath, "codex-cli")
	if !strings.Contains(updated, "[mcp_servers.hasp]") || !strings.Contains(updated, "command = "+strconvQuote(wrapperPath)) {
		t.Fatalf("missing hasp mcp block: %s", updated)
	}
	if strings.Contains(updated, "args =") || strings.Contains(updated, "HASP_HOME =") {
		t.Fatalf("expected wrapper-script config without raw args/env block: %s", updated)
	}

	replaced := upsertCodexMCPServerConfig([]byte(`
model = "gpt-5.4"

[mcp_servers.hasp]
command = "old"

[mcp_servers.hasp.env]
HASP_HOME = "/old"

[notice]
hide = true
`), "/tmp/hasp-home", wrapperPath, "codex-cli")
	if strings.Contains(replaced, "command = \"old\"") || strings.Contains(replaced, "/old") {
		t.Fatalf("old hasp block was not replaced: %s", replaced)
	}
	if !strings.Contains(replaced, "[notice]") {
		t.Fatalf("other codex config sections were lost: %s", replaced)
	}
}

func TestUpsertJSONMCPServerConfigPreservesExistingContent(t *testing.T) {
	wrapperPath := "/tmp/hasp-home/bin/hasp-agent-claude-code"
	updated, err := upsertJSONMCPServerConfig([]byte(`{"theme":"dark","mcpServers":{"other":{"command":"foo","args":["bar"]}}}`), "/tmp/hasp-home", wrapperPath, "claude-code")
	if err != nil {
		t.Fatalf("upsert json config: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(updated, &payload); err != nil {
		t.Fatalf("decode updated config: %v", err)
	}
	if payload["theme"] != "dark" {
		t.Fatalf("expected unrelated config preserved, got %+v", payload)
	}
	mcpServers, ok := payload["mcpServers"].(map[string]any)
	if !ok {
		t.Fatalf("expected mcpServers object, got %+v", payload["mcpServers"])
	}
	if _, ok := mcpServers["other"]; !ok {
		t.Fatalf("expected existing MCP entry preserved, got %+v", mcpServers)
	}
	haspEntry, ok := mcpServers["hasp"].(map[string]any)
	if !ok {
		t.Fatalf("expected hasp entry, got %+v", mcpServers["hasp"])
	}
	if haspEntry["command"] != wrapperPath {
		t.Fatalf("expected absolute hasp command path, got %+v", haspEntry)
	}
	if _, ok := haspEntry["args"]; ok {
		t.Fatalf("expected wrapper-script config without raw args, got %+v", haspEntry["args"])
	}
	if _, ok := haspEntry["env"]; ok {
		t.Fatalf("expected wrapper-script config without raw env, got %+v", haspEntry["env"])
	}
}

func TestPiSettingsPackageConfigPreservesExistingContent(t *testing.T) {
	packagePath := filepath.Join(t.TempDir(), "hasp-home", "pi-package")
	updated, err := upsertPiSettingsPackageConfig([]byte(`{"defaultModel":"sonnet","packages":["/existing/pkg"]}`), packagePath)
	if err != nil {
		t.Fatalf("upsert pi settings: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(updated, &payload); err != nil {
		t.Fatalf("decode updated pi settings: %v", err)
	}
	if payload["defaultModel"] != "sonnet" {
		t.Fatalf("expected unrelated pi setting preserved, got %+v", payload)
	}
	packages, ok := payload["packages"].([]any)
	if !ok || len(packages) != 2 || packages[0] != "/existing/pkg" || packages[1] != packagePath {
		t.Fatalf("expected package appended once, got %+v", payload["packages"])
	}
	second, err := upsertPiSettingsPackageConfig(updated, packagePath)
	if err != nil {
		t.Fatalf("second pi settings upsert: %v", err)
	}
	if !bytes.Equal(updated, second) {
		t.Fatalf("expected idempotent pi settings upsert\nfirst: %s\nsecond: %s", updated, second)
	}
	removed, err := removePiSettingsPackageConfig(second, packagePath)
	if err != nil {
		t.Fatalf("remove pi settings package: %v", err)
	}
	if strings.Contains(string(removed), packagePath) || !strings.Contains(string(removed), "/existing/pkg") {
		t.Fatalf("expected only hasp pi package removed, got %s", string(removed))
	}
	if _, err := upsertPiSettingsPackageConfig([]byte(`{"packages":true}`), packagePath); err == nil {
		t.Fatal("expected non-array pi packages to fail")
	}
	if _, err := removePiSettingsPackageConfig([]byte(`{"packages":true}`), packagePath); err == nil {
		t.Fatal("expected non-array pi packages removal to fail")
	}
}

func TestSetupCommandNonInteractive(t *testing.T) {
	lockAppSeams(t)

	harness := newSetupHarness(t)
	haspHome := filepath.Join(t.TempDir(), "hasp-home")
	repo := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if out, err := run("git", "-C", repo, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	importPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(importPath, []byte("OPENAI_API_KEY=abc123\n"), 0o600); err != nil {
		t.Fatalf("write import file: %v", err)
	}

	keyring := &memorySetupKeyring{}
	origNewStore := newVaultStoreFn
	origRead := setupReadFileFn
	origWrite := setupWriteFileFn
	origMkdir := setupMkdirAllFn
	origRename := setupRenameFn
	origCreateTemp := setupCreateTempFn
	origNow := setupNowFn
	defer func() {
		newVaultStoreFn = origNewStore
		setupReadFileFn = origRead
		setupWriteFileFn = origWrite
		setupMkdirAllFn = origMkdir
		setupRenameFn = origRename
		setupCreateTempFn = origCreateTemp
		setupNowFn = origNow
	}()

	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }
	harness.stubBinary(t, "/opt/homebrew/bin/hasp")
	setupReadFileFn = os.ReadFile
	setupWriteFileFn = os.WriteFile
	setupMkdirAllFn = os.MkdirAll
	setupRenameFn = os.Rename
	setupCreateTempFn = os.CreateTemp
	setupNowFn = func() time.Time { return time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC) }

	t.Setenv("SETUP_MASTER_PASSWORD", "correct horse battery staple")

	var stdout bytes.Buffer
	err := runWithStarter(
		context.Background(),
		[]string{
			"setup",
			"--non-interactive",
			"--hasp-home", haspHome,
			"--repo", repo,
			"--agent", "claude-code",
			"--agent", "cursor",
			"--master-password-env", "SETUP_MASTER_PASSWORD",
			"--import", importPath,
			"--import-format", "env",
			"--bind-imports",
			"--install-hooks=false",
			"--enable-convenience-unlock=true",
		},
		bytes.NewBuffer(nil),
		&stdout,
		io.Discard,
		&fakeStarter{},
	)
	if err != nil {
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
	if len(summary.Imported) != 1 || summary.Imported[0].Alias == "" {
		t.Fatalf("expected imported item with alias, got %+v", summary.Imported)
	}
	if summary.ConvenienceUnlock != "enabled" {
		t.Fatalf("expected enabled convenience unlock, got %+v", summary)
	}
	if len(summary.Agents) != 2 {
		t.Fatalf("expected agent outcomes, got %+v", summary.Agents)
	}

	configPath, err := paths.ConfigPath()
	if err != nil {
		t.Fatalf("config path: %v", err)
	}
	cfgBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read saved cli config: %v", err)
	}
	if !strings.Contains(string(cfgBytes), haspHome) {
		t.Fatalf("saved config missing HASP_HOME: %s", string(cfgBytes))
	}

	statePath := filepath.Join(haspHome, "vault.json.enc")
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("stat vault state: %v", err)
	}

	claudeConfig := filepath.Join(harness.userHome, ".claude.json")
	cursorConfig := filepath.Join(harness.userHome, ".cursor", "mcp.json")
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

	t.Setenv("HASP_HOME", haspHome)
	t.Setenv("HASP_MASTER_PASSWORD", "")
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
	err = runWithStarter(
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
			"--enable-convenience-unlock=true",
			"--overwrite-existing-config=true",
		},
		bytes.NewBuffer(nil),
		&stdout,
		io.Discard,
		&fakeStarter{},
	)
	if err != nil {
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

func TestSetupCommandNonInteractiveWithoutAgents(t *testing.T) {
	lockAppSeams(t)

	userHome := t.TempDir()
	haspHome := filepath.Join(t.TempDir(), "hasp-home")
	keyring := &memorySetupKeyring{}
	origNewStore := newVaultStoreFn
	origHome := setupUserHomeDirFn
	defer func() {
		newVaultStoreFn = origNewStore
		setupUserHomeDirFn = origHome
	}()

	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }
	setupUserHomeDirFn = func() (string, error) { return userHome, nil }

	t.Setenv("HOME", userHome)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(userHome, ".config"))
	t.Setenv("SETUP_MASTER_PASSWORD", "correct horse battery staple")

	var stdout bytes.Buffer
	err := runWithStarter(
		context.Background(),
		[]string{
			"setup",
			"--non-interactive",
			"--hasp-home", haspHome,
			"--master-password-env", "SETUP_MASTER_PASSWORD",
			"--enable-convenience-unlock=false",
		},
		bytes.NewBuffer(nil),
		&stdout,
		io.Discard,
		&fakeStarter{},
	)
	if err != nil {
		t.Fatalf("setup command without agents: %v", err)
	}

	var summary setupSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("decode setup summary without agents: %v", err)
	}
	if summary.InitState != "created" {
		t.Fatalf("unexpected init state without agents: %+v", summary)
	}
	if len(summary.Agents) != 0 {
		t.Fatalf("expected no agent outcomes, got %+v", summary.Agents)
	}
	if summary.Binding != nil {
		t.Fatalf("expected no binding without repo, got %+v", summary.Binding)
	}
}

func TestDetectSelectAndWriteSetupAgentsHelpers(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	cursorConfigPath := filepath.Join(homeDir, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(cursorConfigPath), 0o700); err != nil {
		t.Fatalf("mkdir cursor dir: %v", err)
	}
	if err := os.WriteFile(cursorConfigPath, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write cursor config: %v", err)
	}

	origHome := setupUserHomeDirFn
	origLookPath := setupLookPathFn
	defer func() {
		setupUserHomeDirFn = origHome
		setupLookPathFn = origLookPath
	}()
	setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
	setupLookPathFn = func(name string) (string, error) {
		if name == "codex" {
			return "/usr/bin/codex", nil
		}
		return "", os.ErrNotExist
	}

	detected := detectSetupAgents(setupSupportedAgents())
	if len(detected) != 2 {
		t.Fatalf("expected codex + cursor detection, got %+v", detected)
	}
	if setupAgentBinary("codex-cli") != "codex" || setupAgentBinary("claude-code") != "claude" {
		t.Fatal("unexpected setup agent binary mapping")
	}
	selected, err := selectSetupAgents(setupSupportedAgents(), []string{"codex-cli", "codex-cli", "cursor"})
	if err != nil || len(selected) != 2 {
		t.Fatalf("unexpected selected agents: %+v err=%v", selected, err)
	}
	if _, err := selectSetupAgents(setupSupportedAgents(), []string{"missing"}); err == nil {
		t.Fatal("expected unsupported agent error")
	}
}

func TestSetupPromptsAndHelpers(t *testing.T) {
	lockAppSeams(t)

	prompt := newSetupPrompter(bytes.NewBufferString("custom\nY\nsecret\nsecret2\n"), &bytes.Buffer{})
	value, err := promptString(prompt, "Path", "default")
	if err != nil || value != "custom" {
		t.Fatalf("promptString = %q err=%v", value, err)
	}
	if yes, err := promptBool(prompt, "Enable", false); err != nil || !yes {
		t.Fatal("expected promptYesNo true")
	}
	password, err := promptPassword(prompt, "Password")
	if err != nil || password != "secret" {
		t.Fatalf("promptPassword = %q err=%v", password, err)
	}

	tempFile, err := os.CreateTemp(t.TempDir(), "tty-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
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
	hiddenPrompt := &setupPrompter{reader: bufio.NewReader(strings.NewReader("hidden\n")), out: io.Discard, file: tempFile}
	if password, err := promptPassword(hiddenPrompt, "Password"); err != nil || password != "hidden" {
		t.Fatalf("hidden promptPassword = %q err=%v", password, err)
	}

	var flags setupAgentFlags
	if err := flags.Set(" codex-cli, cursor , "); err != nil {
		t.Fatalf("setupAgentFlags.Set: %v", err)
	}
	if len(flags) != 2 || flags[0] != "codex-cli" || flags[1] != "cursor" {
		t.Fatalf("unexpected setupAgentFlags output: %v", flags)
	}
	if !withinPath("/tmp/repo", "/tmp/repo") || !withinPath("/tmp/repo/sub", "/tmp/repo") || withinPath("/tmp/elsewhere", "/tmp/repo") {
		t.Fatal("unexpected withinPath results")
	}

	origHomeFn := setupUserHomeDirFn
	defer func() { setupUserHomeDirFn = origHomeFn }()
	setupUserHomeDirFn = func() (string, error) { return "/Users/tester", nil }
	if expanded, err := expandHome("~/vault"); err != nil || expanded != "/Users/tester/vault" {
		t.Fatalf("expandHome = %q err=%v", expanded, err)
	}
	if expanded, err := expandHome("/tmp/vault"); err != nil || expanded != "/tmp/vault" {
		t.Fatalf("expandHome absolute = %q err=%v", expanded, err)
	}
}

func TestSetupHelpersConfigAndEnv(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	origHome := setupUserHomeDirFn
	origRead := setupReadFileFn
	origWrite := setupWriteFileFn
	origMkdir := setupMkdirAllFn
	origRename := setupRenameFn
	origCreateTemp := setupCreateTempFn
	origNow := setupNowFn
	defer func() {
		setupUserHomeDirFn = origHome
		setupReadFileFn = origRead
		setupWriteFileFn = origWrite
		setupMkdirAllFn = origMkdir
		setupRenameFn = origRename
		setupCreateTempFn = origCreateTemp
		setupNowFn = origNow
	}()
	setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
	setupReadFileFn = os.ReadFile
	setupWriteFileFn = os.WriteFile
	setupMkdirAllFn = os.MkdirAll
	setupRenameFn = os.Rename
	setupCreateTempFn = os.CreateTemp
	setupNowFn = func() time.Time { return time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC) }

	if err := setupValidateHomePath(filepath.Join(homeDir, ".hasp"), homeDir); err == nil {
		t.Fatal("expected repo-local HASP home rejection")
	}

	if backup, changed, err := setupAtomicWrite(filepath.Join(homeDir, "config.json"), nil, []byte(`{}`)); err != nil || backup != "" || !changed {
		t.Fatalf("setupAtomicWrite initial write: backup=%q changed=%t err=%v", backup, changed, err)
	}
	if backup, changed, err := setupAtomicWrite(filepath.Join(homeDir, "config.json"), []byte(`{}`), []byte(`{}`)); err != nil || backup != "" || changed {
		t.Fatalf("setupAtomicWrite unchanged write: backup=%q changed=%t err=%v", backup, changed, err)
	}
	if backup, changed, err := setupAtomicWrite(filepath.Join(homeDir, "config.json"), []byte(`{}`), []byte(`{"x":1}`)); err != nil || backup == "" || !changed {
		t.Fatalf("setupAtomicWrite backup write: backup=%q changed=%t err=%v", backup, changed, err)
	}

	restore, err := setupSetEnv("HASP_HOME", "/tmp/one")
	if err != nil {
		t.Fatalf("setupSetEnv set: %v", err)
	}
	if got := os.Getenv("HASP_HOME"); got != "/tmp/one" {
		t.Fatalf("unexpected env after set: %q", got)
	}
	restore()
}
