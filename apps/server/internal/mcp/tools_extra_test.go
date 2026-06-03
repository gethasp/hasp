package mcp

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
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
	call.Arguments["session_token"] = 123
	if token, source := mcpSessionToken(call); token != "" || source != mcpSessionTokenNone {
		t.Fatalf("mcpSessionToken non-string = %q source=%d", token, source)
	}
	delete(call.Arguments, "session_token")
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

func TestEnsureMCPSessionRecoversStaleInheritedEnvToken(t *testing.T) {
	assertEnsureMCPSessionRecoversInheritedEnvToken(t, "stale-token", "resolve session: session not found")
}

func TestEnsureMCPSessionKeepsExplicitTokenStrict(t *testing.T) {
	lockMCPSeams(t)
	origEnsureSession := ensureSessionFn
	t.Cleanup(func() { ensureSessionFn = origEnsureSession })
	t.Setenv(mcpEnvSessionToken, "env-token")

	calls := []string{}
	ensureSessionFn = func(_ context.Context, _ string, providedToken string, _ string) (brokerops.Session, error) {
		calls = append(calls, providedToken)
		return brokerops.Session{}, errors.New("resolve session: session not found")
	}

	_, err := ensureMCPSession(context.Background(), toolCall{Arguments: map[string]any{"session_token": "explicit-token"}}, "/repo")
	if err == nil || !strings.Contains(err.Error(), "resolve session: session not found") || !strings.Contains(err.Error(), "omit session_token") {
		t.Fatalf("expected explicit token resolve failure, got %v", err)
	}
	if len(calls) != 1 || calls[0] != "explicit-token" {
		t.Fatalf("ensure calls = %#v", calls)
	}
}

func TestEnsureMCPSessionRecoversWrongProjectInheritedEnvToken(t *testing.T) {
	assertEnsureMCPSessionRecoversInheritedEnvToken(t, "other-project-token", "session project root mismatch: have /other want /repo")
}

func assertEnsureMCPSessionRecoversInheritedEnvToken(t *testing.T, inheritedToken string, inheritedFailure string) {
	t.Helper()
	lockMCPSeams(t)
	origEnsureSession := ensureSessionFn
	t.Cleanup(func() { ensureSessionFn = origEnsureSession })
	t.Setenv(mcpEnvSessionToken, inheritedToken)

	calls := []string{}
	ensureSessionFn = func(_ context.Context, _ string, providedToken string, _ string) (brokerops.Session, error) {
		calls = append(calls, providedToken)
		if providedToken == inheritedToken {
			return brokerops.Session{}, errors.New(inheritedFailure)
		}
		if providedToken == "" {
			return brokerops.Session{Token: "fresh-token"}, nil
		}
		return brokerops.Session{}, errors.New("unexpected token")
	}

	session, err := ensureMCPSession(context.Background(), toolCall{Arguments: map[string]any{}}, "/repo")
	if err != nil {
		t.Fatalf("ensureMCPSession: %v", err)
	}
	if session.Token != "fresh-token" {
		t.Fatalf("session token = %q", session.Token)
	}
	if len(calls) != 2 || calls[0] != inheritedToken || calls[1] != "" {
		t.Fatalf("ensure calls = %#v", calls)
	}
}

func TestEnsureMCPSessionDoesNotRecoverUnrelatedInheritedTokenErrors(t *testing.T) {
	lockMCPSeams(t)
	origEnsureSession := ensureSessionFn
	t.Cleanup(func() { ensureSessionFn = origEnsureSession })
	t.Setenv(mcpEnvSessionToken, "env-token")

	calls := 0
	ensureSessionFn = func(_ context.Context, _ string, providedToken string, _ string) (brokerops.Session, error) {
		calls++
		return brokerops.Session{}, errors.New("resolve session: daemon unavailable")
	}

	_, err := ensureMCPSession(context.Background(), toolCall{Arguments: map[string]any{}}, "/repo")
	if err == nil || err.Error() != "resolve session: daemon unavailable" {
		t.Fatalf("expected daemon failure, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("ensure calls = %d", calls)
	}
	if isRecoverableInheritedSessionError(nil) {
		t.Fatal("nil error should not be recoverable")
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
