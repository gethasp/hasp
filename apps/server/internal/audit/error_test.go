package audit

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestNewAndVerifyFailOnMalformedAuditFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "audit.jsonl"), []byte("{bad json\n"), 0o600); err != nil {
		t.Fatalf("write malformed audit file: %v", err)
	}
	if err := log.Verify(); err == nil {
		t.Fatal("expected verify failure on malformed audit file")
	}
	if _, _, err := log.Checkpoint(); err == nil {
		t.Fatal("expected checkpoint failure on malformed audit file")
	}
}

func TestVerifyMissingFileAndAppendOpenFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if err := log.Verify(); err != nil {
		t.Fatalf("verify missing file: %v", err)
	}
	dirPath := filepath.Join(home, "audit.jsonl")
	if err := os.Mkdir(dirPath, 0o700); err != nil {
		t.Fatalf("mkdir audit dir path: %v", err)
	}
	if _, err := log.Append(EventRun, "tester", map[string]any{}); err == nil {
		t.Fatal("expected append open failure")
	}
}

func TestVerifyScannerFailureOnOversizedLine(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	large := bytes.Repeat([]byte("a"), 1024*1024)
	if err := os.WriteFile(filepath.Join(home, "audit.jsonl"), append(large, '\n'), 0o600); err != nil {
		t.Fatalf("write oversized audit line: %v", err)
	}
	if err := log.Verify(); err == nil {
		t.Fatal("expected scanner failure")
	}
}

func TestAppendFailsWhenEventCannotBeEncoded(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if _, err := log.Append(EventRun, "tester", map[string]any{"bad": func() {}}); err == nil {
		t.Fatal("expected append encode failure")
	}
}

func TestAppendFailsWhenExistingAuditIsMalformed(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "audit.jsonl"), []byte("{bad json\n"), 0o600); err != nil {
		t.Fatalf("write malformed audit file: %v", err)
	}
	if _, err := log.Append(EventRun, "tester", map[string]any{}); err == nil {
		t.Fatal("expected append failure on malformed existing audit")
	}
}

func TestVerifyDetectsSequenceAndPrevHashMismatch(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	badSequence := `{"sequence":2,"timestamp":"2026-04-14T00:00:00Z","type":"run","prev_hash":"","hash":"x"}` + "\n"
	if err := os.WriteFile(filepath.Join(home, "audit.jsonl"), []byte(badSequence), 0o600); err != nil {
		t.Fatalf("write bad sequence: %v", err)
	}
	if err := log.Verify(); err == nil {
		t.Fatal("expected sequence mismatch failure")
	}

	badPrevHash := `{"sequence":1,"timestamp":"2026-04-14T00:00:00Z","type":"run","prev_hash":"bogus","hash":"x"}` + "\n"
	if err := os.WriteFile(filepath.Join(home, "audit.jsonl"), []byte(badPrevHash), 0o600); err != nil {
		t.Fatalf("write bad prev hash: %v", err)
	}
	if err := log.Verify(); err == nil {
		t.Fatal("expected prev-hash mismatch failure")
	}
}

func TestVerifyDetectsHashMismatch(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	badHash := `{"sequence":1,"timestamp":"2026-04-14T00:00:00Z","type":"run","prev_hash":"","hash":"bogus"}` + "\n"
	if err := os.WriteFile(filepath.Join(home, "audit.jsonl"), []byte(badHash), 0o600); err != nil {
		t.Fatalf("write bad hash: %v", err)
	}
	if err := log.Verify(); err == nil {
		t.Fatal("expected hash mismatch failure")
	}
}

func TestAppendFailsWhenAuditDirCannotBeCreated(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "audit.jsonl"), []byte(""), 0o600); err != nil {
		t.Fatalf("write audit file: %v", err)
	}
	log.path = filepath.Join(home, "audit.jsonl", "nested", "audit.jsonl")
	if _, err := log.Append(EventRun, "tester", map[string]any{}); err == nil {
		t.Fatal("expected append mkdir failure")
	}
}

func TestVerifyFailsWhenAuditPathCannotBeOpened(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "audit.jsonl"), []byte(""), 0o600); err != nil {
		t.Fatalf("write audit file: %v", err)
	}
	log.path = filepath.Join(home, "audit.jsonl", "nested")
	if err := log.Verify(); err == nil {
		t.Fatal("expected verify open failure")
	}
}

func TestCheckpointReturnsZeroStateForMissingAudit(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	sequence, hash, err := log.Checkpoint()
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if sequence != 0 || hash != "" {
		t.Fatalf("unexpected empty checkpoint: seq=%d hash=%q", sequence, hash)
	}
}

func TestNewFailsWhenPathResolutionFails(t *testing.T) {
	lockAuditSeams(t)
	origResolve := resolveAuditPaths
	defer func() { resolveAuditPaths = origResolve }()
	resolveAuditPaths = func() (paths.Paths, error) { return paths.Paths{}, fmt.Errorf("resolve fail") }
	if _, err := New(); err == nil {
		t.Fatal("expected path resolution failure")
	}
}

func TestAppendFailsWhenAuditPathCannotOpenOrWrite(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	blocker := filepath.Join(home, "dir")
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatalf("mkdir blocker: %v", err)
	}
	log.path = blocker
	if _, err := log.Append(EventRun, "tester", map[string]any{}); err == nil {
		t.Fatal("expected audit open failure on directory path")
	}
}

func TestAppendFailsWhenEventEncodingFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if _, err := log.Append(EventRun, "tester", map[string]any{"bad": func() {}}); err == nil {
		t.Fatal("expected audit encode failure")
	}
}

type failingAuditWriter struct {
	writeErr error
}

func (f failingAuditWriter) Write([]byte) (int, error) { return 0, f.writeErr }

func (f failingAuditWriter) Close() error { return nil }

func TestAppendFailsWhenMkdirOrWriteFails(t *testing.T) {
	lockAuditSeams(t)
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}

	origMkdir := auditMkdirAll
	origOpen := openAuditFile
	defer func() {
		auditMkdirAll = origMkdir
		openAuditFile = origOpen
	}()

	auditMkdirAll = func(string, os.FileMode) error { return fmt.Errorf("mkdir fail") }
	if _, err := log.Append(EventRun, "tester", map[string]any{}); err == nil || !strings.Contains(err.Error(), "create audit dir") {
		t.Fatalf("expected mkdir failure, got %v", err)
	}

	auditMkdirAll = origMkdir
	openAuditFile = func(string) (auditWriter, error) {
		return failingAuditWriter{writeErr: fmt.Errorf("write fail")}, nil
	}
	if _, err := log.Append(EventRun, "tester", map[string]any{}); err == nil || !strings.Contains(err.Error(), "append audit event") {
		t.Fatalf("expected write failure, got %v", err)
	}

	openAuditFile = func(string) (auditWriter, error) {
		return nil, fmt.Errorf("open fail")
	}
	if _, err := log.Append(EventRun, "tester", map[string]any{}); err == nil || !strings.Contains(err.Error(), "open audit log") {
		t.Fatalf("expected open failure, got %v", err)
	}
}
