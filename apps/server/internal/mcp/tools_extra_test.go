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

func TestMCPOutputCaptureBufferedAndNegativeLimit(t *testing.T) {
	capture := newMCPToolOutputCapture(nil)
	capture.WriteBuffered(nil)
	capture.WriteBuffered([]byte("hello"))
	capture.Close()
	if got := capture.String(); got != "hello" {
		t.Fatalf("capture = %q", got)
	}

	buf := newCappedBuffer(-1)
	if n, err := buf.Write([]byte("hidden")); err != nil || n != len("hidden") {
		t.Fatalf("negative capped write n=%d err=%v", n, err)
	}
	if got := buf.String(); got != "" {
		t.Fatalf("negative limit retained %q", got)
	}
	if got := buf.BytesOmitted(); got != int64(len("hidden")) {
		t.Fatalf("omitted = %d", got)
	}

	limited := newCappedBuffer(3)
	_, _ = limited.Write([]byte("abcdef"))
	if got := limited.String(); got != "abc" {
		t.Fatalf("limited buffer = %q", got)
	}
	if got := limited.BytesOmitted(); got != 3 {
		t.Fatalf("limited omitted = %d", got)
	}
}
