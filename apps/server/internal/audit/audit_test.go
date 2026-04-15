package audit

import (
	"os"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestAppendAndVerify(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, baseDir)

	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	fixedTime := time.Date(2026, 4, 14, 0, 0, 0, 0, time.UTC)
	log.now = func() time.Time { return fixedTime }

	if _, err := log.Append(EventInit, "user", map[string]any{"version": "0.1.0"}); err != nil {
		t.Fatalf("append init: %v", err)
	}
	log.now = func() time.Time { return fixedTime.Add(time.Minute) }
	if _, err := log.Append(EventImport, "user", map[string]any{"source": ".env"}); err != nil {
		t.Fatalf("append import: %v", err)
	}
	if err := log.Verify(); err != nil {
		t.Fatalf("verify audit log: %v", err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, baseDir)

	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if _, err := log.Append(EventInit, "user", map[string]any{"version": "0.1.0"}); err != nil {
		t.Fatalf("append init: %v", err)
	}

	if err := os.WriteFile(log.path, []byte(`{"sequence":1,"timestamp":"2026-04-14T00:00:00Z","type":"init","hash":"tampered"}`+"\n"), 0o600); err != nil {
		t.Fatalf("tamper audit log: %v", err)
	}
	if err := log.Verify(); err == nil {
		t.Fatal("expected tamper detection failure")
	}
}
