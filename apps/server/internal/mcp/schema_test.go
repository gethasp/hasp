package mcp

import "testing"

func TestToolNamesIncludesShippedTools(t *testing.T) {
	names := ToolNames()
	expected := map[string]bool{
		"hasp_list":           false,
		"hasp_check":          false,
		"hasp_targets":        false,
		"hasp_target_explain": false,
		"hasp_run":            false,
		"hasp_inject":         false,
		"hasp_secret_delete":  false,
		"hasp_secret_get":     false,
		"hasp_secret_expose":  false,
		"hasp_secret_hide":    false,
		"hasp_redact":         false,
	}
	for _, name := range names {
		if _, ok := expected[name]; ok {
			expected[name] = true
		}
	}
	for name, found := range expected {
		if !found {
			t.Fatalf("missing tool name %q in %v", name, names)
		}
	}
}

func TestCatalogDoesNotExposeRawSecretWriteToolsByDefault(t *testing.T) {
	for _, tool := range catalog() {
		switch tool.Name {
		case "hasp_capture", "hasp_secret_add", "hasp_secret_update":
			t.Fatalf("default MCP catalog exposed unsafe raw-value tool %q", tool.Name)
		}
		props, _ := tool.InputSchema["properties"].(map[string]any)
		if _, ok := props["value"]; ok {
			t.Fatalf("default MCP tool %q exposed raw value property", tool.Name)
		}
	}
}

func TestCatalogCanExposeUnsafeSecretWriteToolsForTrustedHarness(t *testing.T) {
	t.Setenv(mcpEnvUnsafeWriteTools, "1")
	seen := map[string]bool{
		"hasp_capture":       false,
		"hasp_secret_add":    false,
		"hasp_secret_update": false,
	}
	for _, tool := range catalog() {
		if _, ok := seen[tool.Name]; ok {
			seen[tool.Name] = true
		}
	}
	for name, found := range seen {
		if !found {
			t.Fatalf("missing unsafe tool %q when %s=1", name, mcpEnvUnsafeWriteTools)
		}
	}
}
