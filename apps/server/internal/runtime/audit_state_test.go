package runtime

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestAuditStateTransitions(t *testing.T) {
	now := time.Date(2026, 4, 23, 8, 0, 0, 0, time.UTC)
	state := newAuditState(func() time.Time { return now })
	degraded, degradedAt := state.Snapshot()
	if degraded || degradedAt != nil {
		t.Fatalf("expected healthy initial state")
	}
	state.RecordAppendResult(errors.New("disk full"))
	degraded, degradedAt = state.Snapshot()
	if !degraded || degradedAt == nil || !degradedAt.Equal(now) {
		t.Fatalf("expected first failure timestamp, got degraded=%t at=%v", degraded, degradedAt)
	}
	now = now.Add(time.Minute)
	state.RecordAppendResult(errors.New("still full"))
	_, degradedAt = state.Snapshot()
	if !degradedAt.Equal(time.Date(2026, 4, 23, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("expected repeated failures not to reset timestamp, got %v", degradedAt)
	}
	state.RecordAppendResult(nil)
	degraded, degradedAt = state.Snapshot()
	if degraded || degradedAt != nil {
		t.Fatalf("expected success to clear degradation, got degraded=%t at=%v", degraded, degradedAt)
	}
	state.MarkDegradedAt(now)
	degraded, degradedAt = state.Snapshot()
	if !degraded || degradedAt == nil || !degradedAt.Equal(now) {
		t.Fatalf("expected explicit degraded timestamp, got degraded=%t at=%v", degraded, degradedAt)
	}
	var nilState *AuditState
	nilState.MarkDegradedAt(now)
	newAuditState(nil).RecordAppendResult(nil)
}

func TestNewRPCServerMarksAuditDegradedWhenAuditInitFails(t *testing.T) {
	original := newRuntimeAuditLog
	t.Cleanup(func() { newRuntimeAuditLog = original })
	newRuntimeAuditLog = func() (*audit.Log, error) { return nil, errors.New("audit init failed") }

	server := newRPCServer(paths.Paths{SocketPath: "/tmp/hasp.sock"})
	degraded, degradedAt := server.auditState.Snapshot()
	if !degraded || degradedAt == nil || !degradedAt.Equal(server.startedAt) {
		t.Fatalf("expected startup audit degradation, got degraded=%t at=%v started=%v", degraded, degradedAt, server.startedAt)
	}
}

func TestInstallAuditHMACKeyRejectsUntrustedInputs(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	log, err := audit.New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if err := installAuditHMACKey(log, []byte("short")); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("expected short key rejection, got %v", err)
	}

	original := newRuntimeAuditLog
	t.Cleanup(func() { newRuntimeAuditLog = original })
	newRuntimeAuditLog = func() (*audit.Log, error) { return nil, errors.New("audit init failed") }
	if err := installAuditHMACKey(log, bytes.Repeat([]byte{1}, 32)); err == nil || !strings.Contains(err.Error(), "verify audit HMAC key") {
		t.Fatalf("expected verifier init error, got %v", err)
	}
	newRuntimeAuditLog = original

	t.Setenv("HASP_HOME", t.TempDir())
	log, err = audit.New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if err := installAuditHMACKey(log, bytes.Repeat([]byte{2}, 32)); err == nil || !strings.Contains(err.Error(), "existing keyed audit chain") {
		t.Fatalf("expected missing keyed chain rejection, got %v", err)
	}

	t.Setenv("HASP_HOME", t.TempDir())
	if err := os.MkdirAll(os.Getenv("HASP_HOME"), 0o700); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("HASP_HOME"), "audit.jsonl"), []byte("{bad-json\n"), 0o600); err != nil {
		t.Fatalf("write corrupt audit log: %v", err)
	}
	log, err = audit.New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if err := installAuditHMACKey(log, bytes.Repeat([]byte{3}, 32)); err == nil || !strings.Contains(err.Error(), "verify audit HMAC key") {
		t.Fatalf("expected audit events error, got %v", err)
	}
}
