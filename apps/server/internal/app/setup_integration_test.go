package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		if !strings.Contains(text, "\"command\": \"hasp\"") {
			t.Fatalf("config missing hasp MCP command: %s", text)
		}
		if !strings.Contains(text, "\"HASP_HOME\": "+`"`+haspHome+`"`) {
			t.Fatalf("config missing custom HASP_HOME: %s", text)
		}
	}

	t.Setenv("HASP_HOME", haspHome)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
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
