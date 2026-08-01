package mcp

import (
	"strings"
	"testing"
)

func TestWrapToolResultFallsBackWhenJSONEncodingFails(t *testing.T) {
	result := map[string]any{"not_json": func() {}}
	wrapped := wrapToolResult(result)
	if len(wrapped.Content) != 1 {
		t.Fatalf("content length = %d, want 1", len(wrapped.Content))
	}
	if !strings.Contains(wrapped.Content[0].Text, "failed to encode tool result") {
		t.Fatalf("fallback text = %q", wrapped.Content[0].Text)
	}
	if wrapped.StructuredContent["not_json"] == nil {
		t.Fatal("structured content should preserve original result map")
	}
}
