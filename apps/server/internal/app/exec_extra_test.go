package app

import (
	"context"
	"io"
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

func TestMappingStringNilAndParseGrantScopeDefault(t *testing.T) {
	var mappings mappingFlag
	if mappings.String() != "" {
		t.Fatalf("expected empty mapping string, got %q", mappings.String())
	}
	if scope := parseGrantScope("bogus"); scope != "" {
		t.Fatalf("expected empty grant scope, got %q", scope)
	}
}
