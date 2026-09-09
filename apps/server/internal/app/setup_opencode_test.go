package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientConfigPathsHonorOverridesAndExistingJSONC(t *testing.T) {
	home := t.TempDir()
	t.Setenv("OPENCODE_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	want := filepath.Join(home, ".config", "opencode", "opencode.json")
	if got := setupOpenCodeConfigPath(home); got != want {
		t.Fatalf("default: %q", got)
	}
	if err := os.MkdirAll(filepath.Dir(want), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want+"c", []byte("{// config\n}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := setupOpenCodeConfigPath(home); got != want+"c" {
		t.Fatalf("existing JSONC: %q", got)
	}
	override := filepath.Join(home, "explicit.json")
	t.Setenv("OPENCODE_CONFIG", override)
	if got := setupOpenCodeConfigPath(home); got != override {
		t.Fatalf("explicit: %q", got)
	}
	t.Setenv("CODEX_HOME", home)
	specs, err := selectSetupAgents(setupSupportedAgents(), []string{"codex-cli"})
	if err != nil {
		t.Fatal(err)
	}
	if got := specs[0].ConfigPath(""); got != filepath.Join(home, "config.toml") {
		t.Fatalf("Codex override: %q", got)
	}
}

func TestOpenCodeSetupAndRemovalPreserveUnsupportedConfig(t *testing.T) {
	lockAppSeams(t)
	home := t.TempDir()
	path := filepath.Join(home, "opencode.jsonc")
	spec := setupAgentSpec{ID: "opencode", Format: "opencode-json", ConfigPath: func(string) string { return path }}
	bad := []byte("{ // user comment\n}\n")
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := setupWriteAgentConfigs([]setupAgentSpec{spec}, home); err == nil || !strings.Contains(err.Error(), "OpenCode config") {
		t.Fatalf("unsupported setup: %v", err)
	}
	if err := removeAgentConsumerConfig(spec, path); err == nil {
		t.Fatal("unsupported removal accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(bad) {
		t.Fatalf("unsupported config changed: %s, %v", after, err)
	}
	good := []byte(`{"mcp":{"hasp":{"type":"local","command":["wrapper"],"enabled":true},"other":{"type":"remote","url":"https://example.test"}},"model":"local/test"}`)
	if err := os.WriteFile(path, good, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeAgentConsumerConfig(spec, path); err != nil {
		t.Fatal(err)
	}
	after, err = os.ReadFile(path)
	if err != nil || strings.Contains(string(after), `"hasp"`) || !strings.Contains(string(after), `"other"`) || !strings.Contains(string(after), `"local/test"`) {
		t.Fatalf("removal: %s, %v", after, err)
	}
}

func TestShortTypoSuggestsOnlyOneEdit(t *testing.T) {
	if got, ok := closestMatch("rn", []string{"run", "status"}); !ok || got != "run" {
		t.Fatalf("one edit: %q %t", got, ok)
	}
	if got, ok := closestMatch("zz", []string{"run"}); ok || got != "" {
		t.Fatalf("distant suggestion: %q %t", got, ok)
	}
}
