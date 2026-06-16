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
		"hasp_secret_get":     false,
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
		case "hasp_capture", "hasp_secret_add", "hasp_secret_update", "hasp_secret_delete", "hasp_secret_expose", "hasp_secret_hide":
			t.Fatalf("default MCP catalog exposed unsafe mutation tool %q", tool.Name)
		}
		props, _ := tool.InputSchema["properties"].(map[string]any)
		if _, ok := props["value"]; ok {
			t.Fatalf("default MCP tool %q exposed raw value property", tool.Name)
		}
	}
}

func TestCatalogSchemasAvoidClientRejectedCombinators(t *testing.T) {
	for _, tool := range catalog() {
		if path := schemaCombinatorPath(tool.InputSchema); path != "" {
			t.Fatalf("tool %s advertises schema combinator at %s", tool.Name, path)
		}
	}
}

func TestSecretGetSchemaAdvertisesRecoverableAuthorizationFields(t *testing.T) {
	for _, tool := range catalog() {
		if tool.Name != "hasp_secret_get" {
			continue
		}
		props, _ := tool.InputSchema["properties"].(map[string]any)
		for _, field := range []string{"project_root", "session_token", "grant_project", "host_label", "name"} {
			if _, ok := props[field]; !ok {
				t.Fatalf("hasp_secret_get schema missing %q in %+v", field, props)
			}
		}
		if _, ok := props["value"]; ok {
			t.Fatalf("metadata-only hasp_secret_get schema exposed raw value property")
		}
		return
	}
	t.Fatal("hasp_secret_get missing from catalog")
}

func schemaCombinatorPath(value any) string {
	return schemaCombinatorPathAt(value, "$")
}

func schemaCombinatorPathAt(value any, path string) string {
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range []string{"oneOf", "anyOf", "allOf"} {
			if _, ok := typed[key]; ok {
				return path + "." + key
			}
		}
		for key, child := range typed {
			if found := schemaCombinatorPathAt(child, path+"."+key); found != "" {
				return found
			}
		}
	case []any:
		for _, child := range typed {
			if found := schemaCombinatorPathAt(child, path+"[]"); found != "" {
				return found
			}
		}
	}
	return ""
}

func TestCatalogCanExposeUnsafeSecretWriteToolsForTrustedHarness(t *testing.T) {
	t.Setenv(mcpEnvUnsafeWriteTools, "1")
	seen := map[string]bool{
		"hasp_capture":       false,
		"hasp_secret_add":    false,
		"hasp_secret_update": false,
		"hasp_secret_delete": false,
		"hasp_secret_expose": false,
		"hasp_secret_hide":   false,
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
