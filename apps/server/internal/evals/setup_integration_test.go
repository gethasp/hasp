//go:build integration

package evals

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupCommandEval(t *testing.T) {
	env := newEvalEnv(t)

	userHome := t.TempDir()
	haspHome := filepath.Join(t.TempDir(), "hasp-home")
	importPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(importPath, []byte("OPENAI_API_KEY=abc123\n"), 0o600); err != nil {
		t.Fatalf("write import path: %v", err)
	}

	cmdEnv := env.commandEnv(map[string]string{
		"HOME":                  userHome,
		"HASP_HOME":             haspHome,
		"XDG_CONFIG_HOME":       filepath.Join(userHome, ".config"),
		"SETUP_MASTER_PASSWORD": env.masterPassword,
	})

	stdout, stderr, err := runCmdWithInput(
		t,
		env.projectRoot,
		cmdEnv,
		"",
		env.binary,
		"setup",
		"--non-interactive",
		"--hasp-home", haspHome,
		"--repo", env.projectRoot,
		"--agent", "codex-cli",
		"--agent", "claude-code",
		"--master-password-env", "SETUP_MASTER_PASSWORD",
		"--import", importPath,
		"--bind-imports",
		"--install-hooks=false",
		"--enable-convenience-unlock=false",
	)
	if err != nil {
		t.Fatalf("setup command failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("decode setup output: %v", err)
	}
	if payload["init_state"] != "created" {
		t.Fatalf("unexpected vault state: %+v", payload)
	}
	expectedRoot, err := filepath.EvalSymlinks(env.projectRoot)
	if err != nil {
		t.Fatalf("eval symlinks project root: %v", err)
	}
	projectRoot := payload["project_root"].(string)
	if projectRoot != expectedRoot && projectRoot != filepath.Clean(env.projectRoot) {
		t.Fatalf("unexpected project root: %+v", payload)
	}

	configPath := filepath.Join(userHome, ".codex", "config.toml")
	codexConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read codex config: %v", err)
	}
	if !strings.Contains(string(codexConfig), "[mcp_servers.hasp]") {
		t.Fatalf("codex config missing hasp block: %s", string(codexConfig))
	}

	claudePath := filepath.Join(userHome, ".claude.json")
	claudeConfig, err := os.ReadFile(claudePath)
	if err != nil {
		t.Fatalf("read claude config: %v", err)
	}
	if !strings.Contains(string(claudeConfig), "\"hasp\"") {
		t.Fatalf("claude config missing hasp entry: %s", string(claudeConfig))
	}

	statusOut, _, err := runCmdWithInput(t, env.projectRoot, cmdEnv, "", env.binary, "project", "status", "--project-root", env.projectRoot)
	if err != nil {
		t.Fatalf("project status after setup failed: %v", err)
	}
	if !strings.Contains(statusOut, "OPENAI_API_KEY") {
		t.Fatalf("project status missing imported secret binding: %s", statusOut)
	}

	runOut, _, err := runCmdWithInput(
		t,
		env.projectRoot,
		cmdEnv,
		"",
		env.binary,
		"run",
		"--project-root", env.projectRoot,
		"--env", "OPENAI_API_KEY=secret_01",
		"--grant-project", "window",
		"--grant-secret", "session",
		"--grant-window", "15m",
		"--", "sh", "-c", "printf '%s' \"$OPENAI_API_KEY\"",
	)
	if err != nil {
		t.Fatalf("run after setup failed: %v", err)
	}
	if strings.Contains(runOut, "abc123") {
		t.Fatalf("run leaked managed value after setup: %s", runOut)
	}

	mcpOut, _, err := runCmdWithInput(t, env.projectRoot, cmdEnv, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n", env.binary, "mcp")
	if err != nil {
		t.Fatalf("mcp tools/list failed after setup: %v", err)
	}
	if !strings.Contains(mcpOut, "hasp_list") {
		t.Fatalf("mcp tools/list missing hasp tools: %s", mcpOut)
	}
}
