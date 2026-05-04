package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestExecuteCommandUsageAndResolveValueErrors(t *testing.T) {
	starter := &fakeStarter{err: io.EOF}
	if err := executeCommand(context.Background(), []string{}, io.Discard, io.Discard, false, starter); err == nil {
		t.Fatal("expected executeCommand usage error")
	}
	if err := executeCommand(context.Background(), []string{"--file", "CERT=file_01", "--", "true"}, io.Discard, io.Discard, false, starter); err == nil {
		t.Fatal("expected executeCommand starter/open error")
	}
	if _, err := resolveValue("inline", "path"); err == nil {
		t.Fatal("expected resolveValue conflict error")
	}
}

func TestEnsureClientFailurePath(t *testing.T) {
	starter := &fakeStarter{err: io.EOF}
	if _, err := ensureClient(context.Background(), starter); err == nil {
		t.Fatal("expected ensureClient failure")
	}
}

// hasp-4m2c: inject without --file should suggest `hasp run` for env-only
// delivery rather than implying that --env is unsupported.
func TestInjectMissingFileMentionsHaspRunFallback(t *testing.T) {
	starter := &fakeStarter{err: io.EOF}
	var stdout, stderr bytes.Buffer
	err := injectCommand(context.Background(), []string{"--env", "FOO=@KEY", "--", "env"}, &stdout, &stderr, starter)
	if err == nil {
		t.Fatal("expected injectCommand error when --file is missing")
	}
	msg := err.Error()
	if !strings.Contains(msg, "--file NAME=REFERENCE mapping") {
		t.Fatalf("expected file mapping requirement, got %q", msg)
	}
	if !strings.Contains(msg, "hasp run") {
		t.Fatalf("expected hint pointing at `hasp run` for env-only delivery, got %q", msg)
	}
}

func TestMappingStringNilAndParseGrantScopeDefault(t *testing.T) {
	var mappings mappingFlag
	if mappings.String() != "" {
		t.Fatalf("expected empty mapping string, got %q", mappings.String())
	}
	if scope := parseGrantScope("bogus"); scope != "" {
		t.Fatalf("expected empty grant scope, got %q", scope)
	}
}
