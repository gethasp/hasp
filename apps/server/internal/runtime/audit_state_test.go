package runtime

import (
	"bytes"
	"encoding/json"
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
	state.RecordAppendResult(nil)
	degraded, degradedAt = state.Snapshot()
	if degraded || degradedAt != nil {
		t.Fatalf("expected append success to clear append degradation, got degraded=%t at=%v", degraded, degradedAt)
	}
	verifyFailedAt := now.Add(time.Minute)
	state.MarkVerifyFailedAt(verifyFailedAt)
	state.RecordAppendResult(nil)
	degraded, degradedAt = state.Snapshot()
	if !degraded || degradedAt == nil || !degradedAt.Equal(verifyFailedAt) {
		t.Fatalf("expected verify failure to survive append success, got degraded=%t at=%v", degraded, degradedAt)
	}
	verifiedAt := now.Add(2 * time.Minute)
	state.MarkVerifiedAt(verifiedAt)
	degraded, degradedAt = state.Snapshot()
	if degraded || degradedAt != nil {
		t.Fatalf("expected successful verify to clear verify degradation, got degraded=%t at=%v", degraded, degradedAt)
	}
	if got := state.LastVerifiedAt(); got == nil || !got.Equal(verifiedAt) {
		t.Fatalf("last verified at = %v, want %v", got, verifiedAt)
	}
	var nilState *AuditState
	nilState.RecordAppendResult(errors.New("ignored"))
	nilState.MarkDegradedAt(now)
	nilState.MarkVerifyFailedAt(now)
	nilState.MarkVerifiedAt(now)
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
	if err := installAuditHMACKey(nil, bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatalf("nil audit log should be ignored, got %v", err)
	}
	if err := installAuditHMACKey(log, nil); err != nil {
		t.Fatalf("empty audit key should be ignored, got %v", err)
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

func TestInstallAuditHMACKeyAcceptsKeyedPrefixBeforeExistingCorruption(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	key := bytes.Repeat([]byte{7}, 32)

	seed, err := audit.New()
	if err != nil {
		t.Fatalf("new seed audit log: %v", err)
	}
	first, err := seed.WithKey(key).Append(audit.EventInit, "tester", map[string]any{"phase": "seed"})
	if err != nil {
		t.Fatalf("append keyed seed: %v", err)
	}
	duplicate, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal duplicate: %v", err)
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("HASP_HOME"), "audit.jsonl"), append(duplicate, '\n'), 0o600); err != nil {
		t.Fatalf("overwrite audit log with duplicate: %v", err)
	}
	f, err := os.OpenFile(filepath.Join(os.Getenv("HASP_HOME"), "audit.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open audit log append: %v", err)
	}
	if _, err := f.Write(append(duplicate, '\n')); err != nil {
		_ = f.Close()
		t.Fatalf("append duplicate: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close audit log: %v", err)
	}

	candidate, err := audit.New()
	if err != nil {
		t.Fatalf("new candidate audit log: %v", err)
	}
	if err := installAuditHMACKey(candidate, key); err != nil {
		t.Fatalf("key that verifies intact prefix should be accepted: %v", err)
	}
	if got := candidate.HMACKey(); !bytes.Equal(got, key) {
		t.Fatalf("installed key = %x, want %x", got, key)
	}

	wrongCandidate, err := audit.New()
	if err != nil {
		t.Fatalf("new wrong-key candidate audit log: %v", err)
	}
	wrongKey := bytes.Repeat([]byte{8}, 32)
	if err := installAuditHMACKey(wrongCandidate, wrongKey); err == nil || !strings.Contains(err.Error(), "does not verify existing audit chain") {
		t.Fatalf("wrong key should still be rejected, got %v", err)
	}
}
