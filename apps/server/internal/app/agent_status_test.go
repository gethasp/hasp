package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestAgentStatusDoesNotConfuseInstallationWithConnection(t *testing.T) {
	lockAppSeams(t)
	base := t.TempDir()
	t.Setenv("HASP_HOME", filepath.Join(base, "vault"))
	t.Setenv("HASP_SOCKET", filepath.Join(base, "missing.sock"))
	t.Setenv("HASP_AGENT_SAFE_MODE", "")
	t.Setenv("HASP_SESSION_TOKEN", "")
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(base, "claude"))
	oldOpen := openVaultHandleFn
	openVaultHandleFn = func(context.Context) (*store.Handle, error) {
		t.Fatal("status opened vault")
		return nil, errors.New("unreachable")
	}
	t.Cleanup(func() { openVaultHandleFn = oldOpen })
	status := func() map[string]any {
		t.Helper()
		var out bytes.Buffer
		if err := Run(context.Background(), []string{"agent", "status", "claude-code", "--json"}, strings.NewReader(""), &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		var data map[string]any
		if err := json.Unmarshal(out.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	first := status()
	if first["configuration"] != "missing" || first["configured"] != false || first["connection"] != "not_observed" || first["process_protection"] != "not_observed" {
		t.Fatalf("missing: %+v", first)
	}
	selected, err := selectSetupAgents(setupSupportedAgents(), []string{"claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setupWriteAgentConfigs(selected, os.Getenv("HASP_HOME")); err != nil {
		t.Fatal(err)
	}
	configured := status()
	if configured["configured"] != true || configured["connection"] != "not_observed" || configured["process_protection"] != "not_observed" {
		t.Fatalf("configured: %+v", configured)
	}
	wrapper := configured["wrapper_path"].(string)
	if err := os.Chmod(wrapper, 0o600); err != nil {
		t.Fatal(err)
	}
	if state := status(); state["configured"] != false || state["wrapper"] != "not_executable" {
		t.Fatalf("disabled wrapper: %+v", state)
	}
	if _, err := setupWriteAgentConfigs(selected, os.Getenv("HASP_HOME")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HASP_AGENT_SAFE_MODE", "1")
	guarded := status()
	if guarded["configured"] != true || guarded["process_protection"] != "environment_guard" || guarded["connection"] != "not_observed" {
		t.Fatalf("guarded: %+v", guarded)
	}
}

func TestOpenCodeConfigPreservesOthersAndRejectsUnsupportedInput(t *testing.T) {
	const existing = `{"model":"local/test","mcp":{"other":{"type":"remote","url":"https://example.test/mcp"}}}`
	updated, err := updateOpenCodeMCPConfig([]byte(existing), "/tmp/hasp wrapper", false)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(updated, &config); err != nil {
		t.Fatal(err)
	}
	servers := config["mcp"].(map[string]any)
	if config["model"] != "local/test" || servers["other"] == nil || servers["hasp"].(map[string]any)["type"] != "local" {
		t.Fatalf("updated: %s", updated)
	}
	again, err := updateOpenCodeMCPConfig(updated, "/tmp/hasp wrapper", false)
	if err != nil || !bytes.Equal(updated, again) {
		t.Fatalf("not idempotent: %v", err)
	}
	removed, err := updateOpenCodeMCPConfig(updated, "", true)
	if err != nil || strings.Contains(string(removed), `"hasp"`) || !strings.Contains(string(removed), `"other"`) {
		t.Fatalf("remove: %v %s", err, removed)
	}
	for _, bad := range []string{"null", `{"mcp":[]}`, "{ // preserve this comment\n}", `{"mcp":{"servers":{}}}`, `{"mcp":{},}`} {
		if _, err := updateOpenCodeMCPConfig([]byte(bad), "wrapper", false); err == nil {
			t.Fatalf("accepted unsupported config %q", bad)
		}
	}
}

func TestAgentConfigInspectionDistinguishesDisabledAndOutdated(t *testing.T) {
	base := t.TempDir()
	config := filepath.Join(base, "config.json")
	for _, tc := range []struct{ format, data, want string }{
		{"toml", "[mcp_servers.hasp]\ncommand = \"wrapper\"\n\n[projects.\"/tmp/repo\"]\ntrust_level = \"trusted\"\n", "current"},
		{"toml", "[mcp_servers.hasp]\ncommand = \"wrapper\"\nenabled = false\n", "unverified"},
		{"toml", "[mcp_servers.hasp]\ncommand = \"wrapper\"\n[mcp_servers.hasp.env]\nHASP_HOME = \"other\"\n", "unverified"},
		{"manual", "", "manual"},
		{"json", "null", "unverified"},
		{"json", "{", "unverified"},
		{"json", `{}`, "missing"},
		{"pi-package", `{"packages":[]}`, "missing"},
		{"opencode-json", `{}`, "missing"},
		{"opencode-json", `{"mcp":{"hasp":{"type":"local","command":["other"],"enabled":true}}}`, "unverified"},
		{"json", `{"mcpServers":{"hasp":{"command":"wrapper","disabled":true}}}`, "disabled"},
		{"json", `{"mcpServers":{"hasp":{"command":"wrapper","env":{"HASP_SESSION_TOKEN":"not-to-print"}}}}`, "unverified"},
		{"opencode-json", `{"mcp":{"hasp":{"type":"local","command":["wrapper"],"enabled":false}}}`, "disabled"},
		{"opencode-json", `{"mcp":{"hasp":{"type":"local","command":["wrapper"],"enabled":true}}}`, "current"},
		{"pi-package", `{"packages":[` + strconvQuote(setupPiPackagePath(base)) + `]}`, "outdated"},
	} {
		if err := os.WriteFile(config, []byte(tc.data), 0o600); err != nil {
			t.Fatal(err)
		}
		state, detail := inspectAgentConfig(setupAgentSpec{ID: "pi", Format: tc.format, ConfigPath: func(string) string { return config }}, base, "wrapper")
		if state != tc.want || strings.Contains(detail, "not-to-print") {
			t.Fatalf("%s: %s %s", tc.format, state, detail)
		}
	}
}

func TestAgentWrapperStatusAcceptsOnlyEquivalentExecutablePaths(t *testing.T) {
	lockAppSeams(t)
	base := t.TempDir()
	binary := filepath.Join(base, "hasp")
	if err := os.WriteFile(binary, []byte("fixture executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(binary, alias); err != nil {
		t.Fatal(err)
	}
	oldExecutable := setupExecutableFn
	setupExecutableFn = func() (string, error) { return binary, nil }
	t.Cleanup(func() { setupExecutableFn = oldExecutable })
	data := setupAgentWrapperContent(base, alias, "claude-code")
	if !agentWrapperMatchesCurrentBinary(data, base, "claude-code") {
		t.Fatal("symlink to the running executable reported stale")
	}
	if agentWrapperMatchesCurrentBinary(append(data, []byte("echo changed\n")...), base, "claude-code") {
		t.Fatal("modified wrapper reported current")
	}
	other := filepath.Join(base, "other")
	if err := os.WriteFile(other, []byte("fixture executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if agentWrapperMatchesCurrentBinary(setupAgentWrapperContent(base, other, "claude-code"), base, "claude-code") {
		t.Fatal("distinct executable reported current")
	}
}

func TestAgentStatusReportsFilesystemFailures(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission failures require a non-root user")
	}
	lockAppSeams(t)
	base := t.TempDir()
	t.Setenv("HASP_HOME", base)
	t.Setenv("HASP_SOCKET", filepath.Join(base, "missing.sock"))
	t.Setenv("HASP_SESSION_TOKEN", "")
	t.Setenv("HASP_AGENT_SAFE_MODE", "")
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(base, "claude"))
	selected, err := selectSetupAgents(setupSupportedAgents(), []string{"claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setupWriteAgentConfigs(selected, base); err != nil {
		t.Fatal(err)
	}
	wrapper, err := setupAgentWrapperPath(base, "claude-code")
	if err != nil {
		t.Fatal(err)
	}
	assertState := func(want string) {
		t.Helper()
		result, err := agentStatus(context.Background(), "claude-code")
		if err != nil || result["wrapper"] != want || result["configured"] != false {
			t.Fatalf("status = %v, %v; want wrapper %s and configured false", result, err, want)
		}
	}
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\necho stale\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	assertState("unverified")
	if err := os.Chmod(wrapper, 0o100); err != nil {
		t.Fatal(err)
	}
	assertState("unreadable")
	if err := os.Remove(wrapper); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(wrapper, 0o700); err != nil {
		t.Fatal(err)
	}
	assertState("not_regular")
	if _, err := setupInstallAgentWrapper(base, "hasp", "claude-code"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory wrapper: %v", err)
	}
	if err := os.Chmod(filepath.Dir(wrapper), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(filepath.Dir(wrapper), 0o700); err != nil {
			t.Error(err)
		}
	})
	assertState("unreadable")
	if _, err := setupInstallAgentWrapper(base, "hasp", "claude-code"); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("inaccessible wrapper: %v", err)
	}

	config := selected[0].ConfigPath("")
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(config, 0o700); err != nil {
		t.Fatal(err)
	}
	if state, _ := inspectAgentConfig(selected[0], base, wrapper); state != "unreadable" {
		t.Fatalf("directory config: %s", state)
	}
}

func TestAgentStatusPropagatesPathAndLookupErrors(t *testing.T) {
	lockAppSeams(t)
	oldPaths, oldManager := appResolvePathsFn, secretNewManagerFn
	t.Cleanup(func() { appResolvePathsFn, secretNewManagerFn = oldPaths, oldManager })
	if _, err := agentStatus(context.Background(), "unknown-client"); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unknown client: %v", err)
	}
	want := errors.New("paths unavailable")
	appResolvePathsFn = func() (paths.Paths, error) { return paths.Paths{}, want }
	if _, err := agentStatus(context.Background(), "claude-code"); !errors.Is(err, want) {
		t.Fatalf("paths: %v", err)
	}
	appResolvePathsFn = func() (paths.Paths, error) { return paths.Paths{}, nil }
	if _, err := agentStatus(context.Background(), "claude-code"); err == nil || !strings.Contains(err.Error(), "home is required") {
		t.Fatalf("empty home: %v", err)
	}
	base := t.TempDir()
	appResolvePathsFn = func() (paths.Paths, error) { return paths.Paths{HomeDir: base}, nil }
	t.Setenv("CLAUDE_CONFIG_DIR", base)
	t.Setenv("HASP_SESSION_TOKEN", "expired-token")
	t.Setenv("HASP_AGENT_SAFE_MODE", "")
	secretNewManagerFn = func() (*runtime.Manager, error) { return nil, want }
	result, err := agentStatus(context.Background(), "claude-code")
	if err != nil || result["process_protection"] != "unavailable" || result["session_state"] != "unavailable" || result["connection"] != "not_observed" {
		t.Fatalf("unavailable broker: %v, %v", result, err)
	}
}

func TestAgentStatusAttestsCurrentDaemonSession(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "fixture password")
	t.Setenv("HASP_AGENT_SAFE_MODE", "")
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	client, err := newDaemonTestStarter(t).Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	project := t.TempDir()
	root := filepath.Join(t.TempDir(), "project-link")
	if err := os.Symlink(project, root); err != nil {
		t.Fatal(err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{HostLabel: "status-test", ProjectRoot: root, AgentSafe: true, ConsumerName: "claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HASP_SESSION_TOKEN", reply.SessionToken)
	assertProtection := func(want string) {
		t.Helper()
		result, err := agentStatus(context.Background(), "claude-code")
		if err != nil || result["process_protection"] != want || result["session_id"] != reply.SessionID || result["session_project_root"] != canonicalRoot || result["session_consumer"] != "claude-code" || result["connection"] != "not_observed" {
			t.Fatalf("session status: %v, %v", result, err)
		}
	}
	assertProtection("daemon_session_environment")
	if err := client.RegisterProcess(context.Background(), reply.SessionToken, os.Getpid()); err != nil {
		t.Fatal(err)
	}
	assertProtection("daemon_process_tree")
}

func TestAgentConfigInspectionAcceptsCurrentPiBridge(t *testing.T) {
	base := t.TempDir()
	config := filepath.Join(base, "settings.json")
	packagePath, err := setupInstallPiPackage(base, "wrapper", "pi")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"packages": []string{packagePath}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	state, detail := inspectAgentConfig(setupAgentSpec{ID: "pi", Format: "pi-package", ConfigPath: func(string) string { return config }}, base, "wrapper")
	if state != "current" {
		t.Fatalf("current bridge: %s, %s", state, detail)
	}
}
