package mcp

import (
	"os"
	"testing"
)

func TestMCPDefaultHelpers(t *testing.T) {
	t.Setenv(mcpEnvAgentProjectRoot, "/tmp/project")
	t.Setenv(mcpEnvSessionToken, "session-token")
	t.Setenv(mcpEnvAgentConsumer, "claude-code")

	if got := defaultMCPProjectRoot(); got != "/tmp/project" {
		t.Fatalf("defaultMCPProjectRoot = %q", got)
	}
	if got := defaultOptionalMCPProjectRoot(); got != "/tmp/project" {
		t.Fatalf("defaultOptionalMCPProjectRoot = %q", got)
	}
	call := toolCall{Arguments: map[string]any{}}
	if got := defaultMCPSessionToken(call); got != "session-token" {
		t.Fatalf("defaultMCPSessionToken = %q", got)
	}
	if got := defaultMCPHostLabel(call); got != "agent:claude-code" {
		t.Fatalf("defaultMCPHostLabel = %q", got)
	}

	os.Unsetenv(mcpEnvAgentProjectRoot)
	os.Unsetenv(mcpEnvSessionToken)
	os.Unsetenv(mcpEnvAgentConsumer)
	if got := defaultMCPProjectRoot(); got != "." {
		t.Fatalf("defaultMCPProjectRoot fallback = %q", got)
	}
	if got := defaultOptionalMCPProjectRoot(); got != "" {
		t.Fatalf("defaultOptionalMCPProjectRoot fallback = %q", got)
	}
	if got := defaultMCPSessionToken(call); got != "" {
		t.Fatalf("defaultMCPSessionToken fallback = %q", got)
	}
	if got := defaultMCPHostLabel(call); got != "mcp-stdio" {
		t.Fatalf("defaultMCPHostLabel fallback = %q", got)
	}
}
