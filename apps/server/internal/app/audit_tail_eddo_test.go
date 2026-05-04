package app

// hasp-eddo: audit tail must offer --all (uncap) and --since (duration filter)
// so operators on long-lived installs aren't forced to scroll the default 50.

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

func TestAuditTailAllFlagBypassesDefaultLimit(t *testing.T) {
	lockAppSeams(t)
	base := time.Now().UTC()
	events := make([]audit.Event, 0, 200)
	for i := 1; i <= 200; i++ {
		events = append(events, makeTailEvent(int64(i), audit.EventInjectSafe, "proj/X", base.Add(time.Duration(i)*time.Millisecond)))
	}
	origLog := newAuditLogFn
	origEvents := auditEventsFn
	defer func() { newAuditLogFn = origLog; auditEventsFn = origEvents }()
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return events, nil }

	var buf bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{"tail", "--all"}, &buf); err != nil {
		t.Fatalf("audit tail --all: %v", err)
	}
	lines := nonEmptyLines(buf.String())
	if len(lines) != 200 {
		t.Fatalf("expected 200 lines for --all (got %d):\n%s", len(lines), buf.String())
	}
}

func TestAuditTailAllAndNAreMutuallyExclusive(t *testing.T) {
	lockAppSeams(t)
	origLog := newAuditLogFn
	origEvents := auditEventsFn
	defer func() { newAuditLogFn = origLog; auditEventsFn = origEvents }()
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return nil, nil }

	var buf bytes.Buffer
	err := auditCommandWithArgs(context.Background(), []string{"tail", "--all", "-n", "10"}, &buf)
	if err == nil {
		t.Fatal("expected --all + -n to be rejected as mutually exclusive")
	}
	if !strings.Contains(err.Error(), "--all") || !strings.Contains(err.Error(), "-n") {
		t.Fatalf("conflict error must name both flags: %v", err)
	}
}

func TestAuditTailSinceFiltersByDuration(t *testing.T) {
	lockAppSeams(t)
	now := time.Now().UTC()
	events := []audit.Event{
		makeTailEvent(1, audit.EventInjectSafe, "proj/OLD", now.Add(-2*time.Hour)),
		makeTailEvent(2, audit.EventInjectSafe, "proj/RECENT", now.Add(-30*time.Minute)),
		makeTailEvent(3, audit.EventInjectSafe, "proj/NOW", now.Add(-1*time.Minute)),
	}
	origLog := newAuditLogFn
	origEvents := auditEventsFn
	origNow := auditTailNowFn
	defer func() {
		newAuditLogFn = origLog
		auditEventsFn = origEvents
		auditTailNowFn = origNow
	}()
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return events, nil }
	auditTailNowFn = func() time.Time { return now }

	var buf bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{"tail", "--since", "1h"}, &buf); err != nil {
		t.Fatalf("audit tail --since 1h: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "proj/OLD") {
		t.Fatalf("--since 1h should drop OLD event:\n%s", out)
	}
	if !strings.Contains(out, "proj/RECENT") || !strings.Contains(out, "proj/NOW") {
		t.Fatalf("--since 1h must keep RECENT and NOW events:\n%s", out)
	}
}

func TestAuditTailSinceRejectsNegativeOrZero(t *testing.T) {
	lockAppSeams(t)
	origLog := newAuditLogFn
	origEvents := auditEventsFn
	defer func() { newAuditLogFn = origLog; auditEventsFn = origEvents }()
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return nil, nil }

	var buf bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{"tail", "--since", "0"}, &buf); err == nil {
		t.Fatal("expected --since 0 to be rejected")
	}
	buf.Reset()
	if err := auditCommandWithArgs(context.Background(), []string{"tail", "--since", "-5m"}, &buf); err == nil {
		t.Fatal("expected --since -5m to be rejected")
	}
}
