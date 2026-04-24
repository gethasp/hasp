package runtime

import (
	"errors"
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
