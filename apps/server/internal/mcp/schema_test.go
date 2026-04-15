package mcp

import "testing"

func TestToolNamesIncludesShippedTools(t *testing.T) {
	names := ToolNames()
	expected := map[string]bool{
		"hasp_list":    false,
		"hasp_check":   false,
		"hasp_run":     false,
		"hasp_inject":  false,
		"hasp_capture": false,
		"hasp_redact":  false,
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
