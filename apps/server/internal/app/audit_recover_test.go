package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestAuditRecoverArchivesDegradedLogAndStartsFreshChain(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	key := bytes.Repeat([]byte{7}, sha256.Size)
	setAuditHMACKey(key)
	t.Cleanup(clearAuditHMACKey)

	log := audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(home, "audit.jsonl")}).WithKey(key)
	if _, err := log.Append(audit.EventInit, "tester", map[string]any{"ok": true}); err != nil {
		t.Fatalf("append first event: %v", err)
	}
	file, err := os.OpenFile(filepath.Join(home, "audit.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open audit log for corruption: %v", err)
	}
	if _, err := file.WriteString("not-json\n"); err != nil {
		_ = file.Close()
		t.Fatalf("corrupt audit log: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close corrupted audit log: %v", err)
	}

	recoveryDir := filepath.Join(home, "recovery")
	var out bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{
		"recover",
		"--output", recoveryDir,
		"--reason", "duplicate append at sequence 889",
		"--json",
	}, &out); err != nil {
		t.Fatalf("audit recover: %v", err)
	}

	if _, err := os.Stat(filepath.Join(recoveryDir, "audit.jsonl")); err != nil {
		t.Fatalf("expected archived audit log: %v", err)
	}
	reportData, err := os.ReadFile(filepath.Join(recoveryDir, "recovery-report.json"))
	if err != nil {
		t.Fatalf("expected recovery report: %v", err)
	}
	var report auditRecoveryReport
	if err := json.Unmarshal(reportData, &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.Status != "recovered" || report.ArchiveSHA256 == "" || report.FirstCorruptionAt == nil {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Reason != "duplicate append at sequence 889" {
		t.Fatalf("report reason = %q", report.Reason)
	}
	if err := audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(recoveryDir, "audit.jsonl")}).WithKey(key).Verify(); err == nil {
		t.Fatal("archived degraded log should remain degraded")
	}
	fresh := audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(home, "audit.jsonl")}).WithKey(key)
	if err := fresh.Verify(); err != nil {
		t.Fatalf("fresh audit log should verify: %v", err)
	}
	events, err := fresh.Events()
	if err != nil {
		t.Fatalf("read fresh events: %v", err)
	}
	if len(events) != 1 || events[0].Type != "audit.recovery.rotate" {
		t.Fatalf("fresh events = %+v", events)
	}
	if !strings.Contains(out.String(), `"status":"recovered"`) {
		t.Fatalf("json output missing recovered status: %s", out.String())
	}
}

func TestAuditRecoverRefusesHealthyChainWithoutForce(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	key := bytes.Repeat([]byte{8}, sha256.Size)
	setAuditHMACKey(key)
	t.Cleanup(clearAuditHMACKey)

	log := audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(home, "audit.jsonl")}).WithKey(key)
	if _, err := log.Append(audit.EventInit, "tester", map[string]any{"ok": true}); err != nil {
		t.Fatalf("append event: %v", err)
	}
	err := auditCommandWithArgs(context.Background(), []string{"recover", "--output", filepath.Join(home, "recovery")}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "recovery not needed") {
		t.Fatalf("expected healthy refusal, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(home, "recovery", "audit.jsonl")); !os.IsNotExist(statErr) {
		t.Fatalf("healthy recover should not archive, stat err=%v", statErr)
	}
}
