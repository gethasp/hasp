package store

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestCaptureCreatesAliasAndAudit(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	projectRoot := t.TempDir()
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{}, PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	result, err := handle.Capture(context.Background(), projectRoot, "api_token", ItemKindKV, []byte("abc123"), true)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if result.Alias == "" || result.Reference == "" {
		t.Fatalf("expected alias/reference in capture result: %+v", result)
	}
	if result.Reference != result.Alias {
		t.Fatalf("expected reference to equal alias for bound capture: %+v", result)
	}
	data, err := os.ReadFile(store.paths.AuditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(data), "\"reference\":\""+result.Reference+"\"") {
		t.Fatalf("expected capture audit entry, got %s", string(data))
	}
}

func TestCaptureWithoutBindingKeepsCanonicalReference(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	result, err := handle.Capture(context.Background(), t.TempDir(), "api_token", ItemKindKV, []byte("abc123"), false)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if result.Reference != "api_token" || result.Alias != "" {
		t.Fatalf("unexpected non-bound capture result: %+v", result)
	}
}

func TestCaptureWithoutAuditLoggerStillSucceeds(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	store.audit = nil
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.Capture(context.Background(), t.TempDir(), "api_token", ItemKindKV, []byte("abc123"), false); err != nil {
		t.Fatalf("capture without audit: %v", err)
	}
}
