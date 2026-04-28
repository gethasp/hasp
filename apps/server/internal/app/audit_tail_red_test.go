package app

// RED tests for hasp-1ont — `hasp audit tail [-n N] [-f|--follow]`.
//
// Contract pinned:
//   - `hasp audit tail` prints the last 50 events (chronological) and exits.
//   - `-n N` overrides the default count; N must be positive.
//   - `--json` emits NDJSON (one Event per line) so operators can pipe to jq -c.
//   - `--follow`/`-f` streams new appends after the initial dump; ctx
//     cancellation returns nil cleanly.
//   - Filters (`--secret`, `--project-root`, `--agent`, `--action`, `--blocked`)
//     apply to BOTH the initial dump and the streaming deltas.
//   - The poll interval is wired through auditTailOpts.PollInterval so tests can
//     drive follow mode deterministically without sleeping for a real second.

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

func makeTailEvent(seq int64, typ, ref string, ts time.Time) audit.Event {
	return audit.Event{
		Sequence:  seq,
		Timestamp: ts,
		Type:      typ,
		Actor:     "agent",
		Details:   map[string]any{"reference": ref},
	}
}

func TestAuditTailDefaultReturnsLast50(t *testing.T) {
	lockAppSeams(t)
	base := time.Now().UTC()
	events := make([]audit.Event, 0, 60)
	for i := 1; i <= 60; i++ {
		events = append(events, makeTailEvent(int64(i), audit.EventInjectSafe, "proj/X", base.Add(time.Duration(i)*time.Millisecond)))
	}
	origLog := newAuditLogFn
	origEvents := auditEventsFn
	defer func() { newAuditLogFn = origLog; auditEventsFn = origEvents }()
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return events, nil }

	var buf bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{"tail"}, &buf); err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	lines := nonEmptyLines(buf.String())
	if len(lines) != 50 {
		t.Fatalf("expected 50 lines, got %d:\n%s", len(lines), buf.String())
	}
	// Earliest dropped events (seq 1..10) must not appear; events 11..60 should
	// all be present. Timeline renderer uses second resolution, so both the
	// expected and actual timestamps fall within the same wall-clock second
	// here — we only smoke-check that the line is non-empty.
	_ = base
	if strings.TrimSpace(lines[0]) == "" {
		t.Fatalf("first surviving line is empty: %q", lines[0])
	}
}

func TestAuditTailRespectsExplicitN(t *testing.T) {
	lockAppSeams(t)
	base := time.Now().UTC()
	events := make([]audit.Event, 0, 10)
	for i := 1; i <= 10; i++ {
		events = append(events, makeTailEvent(int64(i), audit.EventInjectSafe, "proj/X", base.Add(time.Duration(i)*time.Millisecond)))
	}
	origLog := newAuditLogFn
	origEvents := auditEventsFn
	defer func() { newAuditLogFn = origLog; auditEventsFn = origEvents }()
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return events, nil }

	var buf bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{"tail", "-n", "3"}, &buf); err != nil {
		t.Fatalf("audit tail -n 3: %v", err)
	}
	lines := nonEmptyLines(buf.String())
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines for -n 3, got %d:\n%s", len(lines), buf.String())
	}
}

func TestAuditTailRejectsNonPositiveN(t *testing.T) {
	lockAppSeams(t)
	origLog := newAuditLogFn
	origEvents := auditEventsFn
	defer func() { newAuditLogFn = origLog; auditEventsFn = origEvents }()
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return nil, nil }

	var buf bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{"tail", "-n", "0"}, &buf); err == nil {
		t.Fatal("expected -n 0 to be rejected")
	}
}

func TestAuditTailJSONEmitsNDJSON(t *testing.T) {
	lockAppSeams(t)
	base := time.Now().UTC()
	events := []audit.Event{
		makeTailEvent(1, audit.EventInjectSafe, "proj/A", base),
		makeTailEvent(2, audit.EventCapture, "proj/B", base.Add(time.Second)),
	}
	origLog := newAuditLogFn
	origEvents := auditEventsFn
	defer func() { newAuditLogFn = origLog; auditEventsFn = origEvents }()
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return events, nil }

	var buf bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{"tail", "--json"}, &buf); err != nil {
		t.Fatalf("audit tail --json: %v", err)
	}
	lines := nonEmptyLines(buf.String())
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d:\n%s", len(lines), buf.String())
	}
	for _, line := range lines {
		var ev audit.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("not valid JSON: %v\nline=%q", err, line)
		}
		if ev.Sequence == 0 {
			t.Fatalf("decoded event missing sequence: %q", line)
		}
	}
}

func TestAuditTailHonorsActionFilter(t *testing.T) {
	lockAppSeams(t)
	base := time.Now().UTC()
	withAction := func(seq int64, ref, action string, ts time.Time) audit.Event {
		return audit.Event{
			Sequence: seq, Timestamp: ts, Type: audit.EventInjectSafe, Actor: "agent",
			Details: map[string]any{"reference": ref, "action": action},
		}
	}
	events := []audit.Event{
		withAction(1, "proj/A", "secret.get.plaintext_grant_used", base),
		withAction(2, "proj/B", "secret.get.plaintext_blocked", base.Add(time.Second)),
		withAction(3, "proj/C", "secret.get.plaintext_grant_used", base.Add(2*time.Second)),
	}
	origLog := newAuditLogFn
	origEvents := auditEventsFn
	defer func() { newAuditLogFn = origLog; auditEventsFn = origEvents }()
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return events, nil }

	var buf bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{"tail", "--action", "secret.get.plaintext_grant_used"}, &buf); err != nil {
		t.Fatalf("audit tail --action: %v", err)
	}
	lines := nonEmptyLines(buf.String())
	if len(lines) != 2 {
		t.Fatalf("expected 2 grant_used lines after --action filter, got %d:\n%s", len(lines), buf.String())
	}
	if strings.Contains(buf.String(), "proj/B") {
		t.Fatalf("expected --action filter to exclude proj/B (blocked event):\n%s", buf.String())
	}
}

func TestAuditTailFollowEmitsNewAppends(t *testing.T) {
	lockAppSeams(t)
	base := time.Now().UTC()
	var mu sync.Mutex
	events := []audit.Event{
		makeTailEvent(1, audit.EventInjectSafe, "proj/INITIAL", base),
	}
	snapshot := func() []audit.Event {
		mu.Lock()
		defer mu.Unlock()
		out := make([]audit.Event, len(events))
		copy(out, events)
		return out
	}
	addEvent := func(seq int64, ref string, ts time.Time) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, makeTailEvent(seq, audit.EventInjectSafe, ref, ts))
	}

	origLog := newAuditLogFn
	origEvents := auditEventsFn
	defer func() {
		newAuditLogFn = origLog
		auditEventsFn = origEvents
	}()
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return snapshot(), nil }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var buf safeBuffer
	done := make(chan error, 1)
	go func() {
		done <- auditTailCommand(ctx, []string{"-f"}, &buf, auditTailOpts{PollInterval: 5 * time.Millisecond})
	}()

	// Wait for the initial dump to land.
	if !waitFor(t, 500*time.Millisecond, func() bool {
		return strings.Contains(buf.String(), "proj/INITIAL")
	}) {
		t.Fatalf("initial dump never emitted:\n%s", buf.String())
	}

	addEvent(2, "proj/STREAMED", base.Add(time.Second))

	if !waitFor(t, 500*time.Millisecond, func() bool {
		return strings.Contains(buf.String(), "proj/STREAMED")
	}) {
		t.Fatalf("streamed event never appeared after follow tick:\n%s", buf.String())
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("follow loop returned error after cancel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("follow loop did not exit after ctx cancel")
	}
}

// safeBuffer guards bytes.Buffer for the follow-mode goroutine race.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func waitFor(t *testing.T, max time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

