//go:build integration

package evals

import (
	"encoding/json"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
)

func TestSetupCommandEval(t *testing.T) {
	env := newEvalEnv(t)

	userHome := t.TempDir()
	haspHome := filepath.Join(t.TempDir(), "hasp-home")
	t.Cleanup(func() {
		stopEvalDaemon(t, env.withScopedHome(haspHome, userHome))
	})
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
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", filepath.Dir(env.binary)+":"+origPath)

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
	if strings.Contains(string(codexConfig), "command = \"hasp\"") {
		t.Fatalf("codex config still uses bare hasp command: %s", string(codexConfig))
	}
	if !strings.Contains(string(codexConfig), "command = \"/") {
		t.Fatalf("codex config missing absolute command path: %s", string(codexConfig))
	}

	claudePath := filepath.Join(userHome, ".claude.json")
	claudeConfig, err := os.ReadFile(claudePath)
	if err != nil {
		t.Fatalf("read claude config: %v", err)
	}
	if !strings.Contains(string(claudeConfig), "\"hasp\"") {
		t.Fatalf("claude config missing hasp entry: %s", string(claudeConfig))
	}
	if strings.Contains(string(claudeConfig), "\"command\":\"hasp\"") || strings.Contains(string(claudeConfig), "\"command\": \"hasp\"") {
		t.Fatalf("claude config still uses bare hasp command: %s", string(claudeConfig))
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

func TestSetupConvenienceUnlockRegressionEval(t *testing.T) {
	env := newEvalEnv(t)

	userHome := t.TempDir()
	haspHome := filepath.Join(t.TempDir(), "hasp-home")
	t.Cleanup(func() {
		stopEvalDaemon(t, env.withScopedHome(haspHome, userHome))
	})
	cmdEnv := env.commandEnv(map[string]string{
		"HOME":                  userHome,
		"HASP_HOME":             haspHome,
		"XDG_CONFIG_HOME":       filepath.Join(userHome, ".config"),
		"SETUP_MASTER_PASSWORD": env.masterPassword,
	})
	if goruntime.GOOS == "darwin" {
		securityStub := filepath.Join(t.TempDir(), "security-fail.sh")
		if err := os.WriteFile(securityStub, []byte("#!/usr/bin/env bash\nexit 1\n"), 0o700); err != nil {
			t.Fatalf("write security stub: %v", err)
		}
		cmdEnv = append(cmdEnv, "HASP_TEST_SECURITY_BIN="+securityStub)
	}

	stdout, stderr, err := runCmdWithInput(
		t,
		env.projectRoot,
		cmdEnv,
		"",
		env.binary,
		"setup",
		"--non-interactive",
		"--json",
		"--hasp-home", haspHome,
		"--repo", env.projectRoot,
		"--agent", "codex-cli",
		"--master-password-env", "SETUP_MASTER_PASSWORD",
		"--install-hooks=false",
		"--enable-convenience-unlock=false",
		"--overwrite-existing-config=true",
	)
	if err != nil {
		t.Fatalf("initial setup failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	stdout, stderr, err = runCmdWithInput(
		t,
		env.projectRoot,
		cmdEnv,
		"",
		env.binary,
		"setup",
		"--non-interactive",
		"--json",
		"--hasp-home", haspHome,
		"--repo", env.projectRoot,
		"--agent", "codex-cli",
		"--master-password-env", "SETUP_MASTER_PASSWORD",
		"--install-hooks=false",
		"--enable-convenience-unlock=ask",
		"--overwrite-existing-config=true",
	)
	if err != nil {
		t.Fatalf("rerun setup failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("decode rerun setup output: %v", err)
	}
	if payload["init_state"] != "existing" {
		t.Fatalf("expected existing vault state, got %+v", payload)
	}
	if payload["convenience_unlock"] != "unavailable" {
		t.Fatalf("expected unavailable convenience unlock, got %+v", payload)
	}

	noPasswordEnv := env.commandEnv(map[string]string{
		"HOME":                 userHome,
		"HASP_HOME":            haspHome,
		"HASP_MASTER_PASSWORD": "",
		"XDG_CONFIG_HOME":      filepath.Join(userHome, ".config"),
	})
	if goruntime.GOOS == "darwin" {
		for _, entry := range cmdEnv {
			if strings.HasPrefix(entry, "HASP_TEST_SECURITY_BIN=") {
				noPasswordEnv = append(noPasswordEnv, entry)
			}
		}
	}

	statusOut, statusErr, err := runCmdWithInput(
		t,
		env.projectRoot,
		noPasswordEnv,
		"",
		env.binary,
		"project", "status", "--project-root", env.projectRoot,
	)
	if err == nil {
		t.Fatalf("expected project status failure without master password when convenience unlock is unavailable\nstdout:\n%s\nstderr:\n%s", statusOut, statusErr)
	}
	if !strings.Contains(statusErr, "HASP_MASTER_PASSWORD is not set and convenience unlock is unavailable") {
		t.Fatalf("expected clearer convenience unlock error, got stdout=%q stderr=%q", statusOut, statusErr)
	}
}

func TestSetupExistingVaultPasswordRetryEval(t *testing.T) {
	env := newEvalEnv(t)

	userHome := t.TempDir()
	haspHome := filepath.Join(t.TempDir(), "hasp-home")
	t.Cleanup(func() {
		stopEvalDaemon(t, env.withScopedHome(haspHome, userHome))
	})
	baseEnv := env.commandEnv(map[string]string{
		"HOME":                  userHome,
		"HASP_HOME":             haspHome,
		"XDG_CONFIG_HOME":       filepath.Join(userHome, ".config"),
		"SETUP_MASTER_PASSWORD": env.masterPassword,
	})

	stdout, stderr, err := runCmdWithInput(
		t,
		env.projectRoot,
		baseEnv,
		"",
		env.binary,
		"setup",
		"--non-interactive",
		"--json",
		"--hasp-home", haspHome,
		"--repo", env.projectRoot,
		"--agent", "codex-cli",
		"--master-password-env", "SETUP_MASTER_PASSWORD",
		"--install-hooks=false",
		"--enable-convenience-unlock=false",
		"--overwrite-existing-config=true",
	)
	if err != nil {
		t.Fatalf("initial setup failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	input := "n\nn\ny\nwrong-password\n" + env.masterPassword + "\n"
	retryEnv := env.commandEnv(map[string]string{
		"HOME":            userHome,
		"HASP_HOME":       haspHome,
		"XDG_CONFIG_HOME": filepath.Join(userHome, ".config"),
	})
	stdout, stderr, err = runCmdWithInput(
		t,
		env.projectRoot,
		retryEnv,
		input,
		env.binary,
		"setup",
		"--hasp-home", haspHome,
		"--agent", "codex-cli",
		"--auto-protect-repos=true",
		"--install-hooks=false",
		"--enable-convenience-unlock=false",
		"--overwrite-existing-config=true",
	)
	if err != nil {
		t.Fatalf("interactive setup retry flow failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if !strings.Contains(stderr, "invalid master password") {
		t.Fatalf("expected invalid-password retry message, got stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stdout, "Setup complete") {
		t.Fatalf("expected setup to complete after retry, got stdout=%q stderr=%q", stdout, stderr)
	}
}
