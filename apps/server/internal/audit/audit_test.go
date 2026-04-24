package audit

import (
	"os"
	"path/filepath"
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
	events, err := log.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(events) != 2 || events[0].Type != EventInit || events[1].Type != EventImport {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestEventsMissingLogAndMalformedLog(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, baseDir)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	events, err := log.Events()
	if err != nil || len(events) != 0 {
		t.Fatalf("missing events = %+v err=%v", events, err)
	}
	if err := os.MkdirAll(filepath.Dir(log.path), 0o700); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	if err := os.WriteFile(log.path, []byte("{bad-json}\n"), 0o600); err != nil {
		t.Fatalf("write malformed audit log: %v", err)
	}
	if _, err := log.Events(); err == nil {
		t.Fatal("expected malformed audit event error")
	}
	blockingFile := filepath.Join(baseDir, "blocking-file")
	if err := os.WriteFile(blockingFile, []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}
	log.path = filepath.Join(blockingFile, "audit.jsonl")
	if _, err := log.Events(); err == nil {
		t.Fatal("expected open audit log failure")
	}
	log.path = filepath.Join(baseDir, "audit-dir")
	if err := os.MkdirAll(log.path, 0o700); err != nil {
		t.Fatalf("mkdir audit dir: %v", err)
	}
	if _, err := log.Events(); err == nil {
		t.Fatal("expected scan audit directory failure")
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
