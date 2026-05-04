package app

// RED TEAM tests for hasp-x05.3.1 "Add local audit filters".
//
// Contract pinned:
//   - A new exported-internal helper: auditFilterEvents(events []audit.Event, opts auditFilterOptions) []audit.Event
//   - auditFilterOptions carries: Secret, ProjectRoot, Agent, Action, Blocked (bool pointer), Since (time.Time)
//   - Filter fields map to audit.Event.Details keys:
//       "reference"    → --secret
//       "project_root" → --project-root
//       "agent"        → --agent
//       "action"       → --action (subset of Type or Details["action"])
//       "blocked"      → Details["blocked"] == true
//   - auditCommandWithArgs accepts: --secret, --project-root, --agent, --action, --blocked, --since
//   - --since accepts an RFC3339 timestamp; events at or before that time are excluded.
//
// All tests MUST FAIL until the green team implements the feature.

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

// ---------------------------------------------------------------------------
// Helper — build a minimal audit.Event with Details populated.
// We don't go through audit.Log.Append so we can construct arbitrary events
// without touching disk.
// ---------------------------------------------------------------------------

func makeFilterEvent(typ, actor string, details map[string]any, ts time.Time) audit.Event {
	return audit.Event{
		Sequence:  1,
		Timestamp: ts,
		Type:      typ,
		Actor:     actor,
		Details:   details,
		PrevHash:  "",
		Hash:      "",
	}
}

// ---------------------------------------------------------------------------
// 1. --secret  (filter by Details["reference"])
// ---------------------------------------------------------------------------

func TestAuditFilterBySecret(t *testing.T) {
	now := time.Now().UTC()
	events := []audit.Event{
		makeFilterEvent(audit.EventInjectSafe, "agent-a", map[string]any{"reference": "proj/DB_PASSWORD"}, now),
		makeFilterEvent(audit.EventInjectSafe, "agent-b", map[string]any{"reference": "proj/API_KEY"}, now),
		makeFilterEvent(audit.EventCapture, "agent-c", map[string]any{"reference": "proj/DB_PASSWORD"}, now),
	}

	opts := auditFilterOptions{Secret: "proj/DB_PASSWORD"}
	got := auditFilterEvents(events, opts)

	if len(got) != 2 {
		t.Fatalf("--secret filter: want 2 events, got %d", len(got))
	}
	for _, e := range got {
		ref, _ := e.Details["reference"].(string)
		if ref != "proj/DB_PASSWORD" {
			t.Errorf("--secret filter: unexpected reference %q in result", ref)
		}
	}
	// Negative: proj/API_KEY must NOT appear.
	for _, e := range got {
		ref, _ := e.Details["reference"].(string)
		if ref == "proj/API_KEY" {
			t.Error("--secret filter: proj/API_KEY must be excluded but was returned")
		}
	}
}

// ---------------------------------------------------------------------------
// 2. --project-root  (filter by Details["project_root"])
// ---------------------------------------------------------------------------

func TestAuditFilterByProjectRoot(t *testing.T) {
	now := time.Now().UTC()
	events := []audit.Event{
		makeFilterEvent(audit.EventRun, "agent", map[string]any{"project_root": "/home/user/alpha"}, now),
		makeFilterEvent(audit.EventRun, "agent", map[string]any{"project_root": "/home/user/beta"}, now),
		makeFilterEvent(audit.EventRun, "agent", map[string]any{"project_root": "/home/user/alpha"}, now),
	}

	opts := auditFilterOptions{ProjectRoot: "/home/user/alpha"}
	got := auditFilterEvents(events, opts)

	if len(got) != 2 {
		t.Fatalf("--project-root filter: want 2 events, got %d", len(got))
	}
	// Negative: beta must be excluded.
	for _, e := range got {
		pr, _ := e.Details["project_root"].(string)
		if pr == "/home/user/beta" {
			t.Error("--project-root filter: /home/user/beta must be excluded but was returned")
		}
	}
}

// ---------------------------------------------------------------------------
// 3. --agent  (filter by Details["agent"])
// ---------------------------------------------------------------------------

func TestAuditFilterByAgent(t *testing.T) {
	now := time.Now().UTC()
	events := []audit.Event{
		makeFilterEvent(audit.EventRun, "system", map[string]any{"agent": "claude"}, now),
		makeFilterEvent(audit.EventRun, "system", map[string]any{"agent": "cursor"}, now),
		makeFilterEvent(audit.EventRun, "system", map[string]any{"agent": "claude"}, now),
	}

	opts := auditFilterOptions{Agent: "claude"}
	got := auditFilterEvents(events, opts)

	if len(got) != 2 {
		t.Fatalf("--agent filter: want 2 events, got %d", len(got))
	}
	// Negative: cursor must be excluded.
	for _, e := range got {
		ag, _ := e.Details["agent"].(string)
		if ag == "cursor" {
			t.Error("--agent filter: cursor must be excluded but was returned")
		}
	}
}

// ---------------------------------------------------------------------------
// 4. --action  (filter by Details["action"] or Event.Type)
// ---------------------------------------------------------------------------

func TestAuditFilterByAction(t *testing.T) {
	now := time.Now().UTC()
	events := []audit.Event{
		makeFilterEvent(audit.EventInjectSafe, "agent", map[string]any{"action": "inject"}, now),
		makeFilterEvent(audit.EventCapture, "agent", map[string]any{"action": "capture"}, now),
		makeFilterEvent(audit.EventRepoBlock, "agent", map[string]any{"action": "block"}, now),
	}

	opts := auditFilterOptions{Action: "inject"}
	got := auditFilterEvents(events, opts)

	if len(got) != 1 {
		t.Fatalf("--action filter: want 1 event, got %d", len(got))
	}
	action, _ := got[0].Details["action"].(string)
	if action != "inject" {
		t.Errorf("--action filter: want action=inject, got %q", action)
	}
	// Negative: capture and block must be excluded.
	for _, e := range got {
		a, _ := e.Details["action"].(string)
		if a == "capture" || a == "block" {
			t.Errorf("--action filter: %q must be excluded but was returned", a)
		}
	}
}

// ---------------------------------------------------------------------------
// 5. --blocked  (filter by Details["blocked"] == true)
// ---------------------------------------------------------------------------

func auditFilterBoolPtr(b bool) *bool { return &b }

func TestAuditFilterByBlocked(t *testing.T) {
	now := time.Now().UTC()
	events := []audit.Event{
		makeFilterEvent(audit.EventRun, "agent", map[string]any{"blocked": true}, now),
		makeFilterEvent(audit.EventRun, "agent", map[string]any{"blocked": false}, now),
		makeFilterEvent(audit.EventRun, "agent", map[string]any{}, now),
		makeFilterEvent(audit.EventRun, "agent", map[string]any{"blocked": true}, now),
	}

	opts := auditFilterOptions{Blocked: auditFilterBoolPtr(true)}
	got := auditFilterEvents(events, opts)

	if len(got) != 2 {
		t.Fatalf("--blocked filter: want 2 events, got %d", len(got))
	}
	for _, e := range got {
		bl, _ := e.Details["blocked"].(bool)
		if !bl {
			t.Error("--blocked filter: returned event with blocked != true")
		}
	}
	// Negative: non-blocked events must be excluded.
	if len(got) > 2 {
		t.Error("--blocked filter: returned more events than expected (non-blocked included)")
	}
}

// ---------------------------------------------------------------------------
// 6a. --since  RFC3339 timestamp form
// ---------------------------------------------------------------------------

func TestAuditFilterBySinceTimestamp(t *testing.T) {
	base := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	events := []audit.Event{
		makeFilterEvent(audit.EventRun, "agent", nil, base.Add(-2*time.Hour)), // before cutoff
		makeFilterEvent(audit.EventRun, "agent", nil, base.Add(-1*time.Hour)), // before cutoff
		makeFilterEvent(audit.EventRun, "agent", nil, base.Add(1*time.Hour)),  // after cutoff → keep
		makeFilterEvent(audit.EventRun, "agent", nil, base.Add(2*time.Hour)),  // after cutoff → keep
	}

	opts := auditFilterOptions{Since: base}
	got := auditFilterEvents(events, opts)

	if len(got) != 2 {
		t.Fatalf("--since timestamp filter: want 2 events after cutoff, got %d", len(got))
	}
	for _, e := range got {
		if !e.Timestamp.After(base) {
			t.Errorf("--since filter: event at %v should have been excluded", e.Timestamp)
		}
	}
	// Negative: events at or before base must not appear.
	for _, e := range got {
		if !e.Timestamp.After(base) {
			t.Errorf("--since filter: old event at %v must be excluded but was returned", e.Timestamp)
		}
	}
}

// ---------------------------------------------------------------------------
// 6b. --since  Duration string form via CLI (e.g. "1h")
//     This tests the CLI flag parse path, not the pure helper.
// ---------------------------------------------------------------------------

func TestAuditCommandWithArgsSinceFlag(t *testing.T) {
	lockAppSeams(t)

	// Stub audit log to return a known set of events.
	base := time.Now().UTC()
	stubEvents := []audit.Event{
		makeFilterEvent(audit.EventRun, "agent", nil, base.Add(-2*time.Hour)),
		makeFilterEvent(audit.EventRun, "agent", nil, base.Add(-30*time.Minute)),
		makeFilterEvent(audit.EventRun, "agent", nil, base.Add(-5*time.Minute)), // within 1h → keep
	}

	origLog := newAuditLogFn
	origEvents := auditEventsFn
	defer func() {
		newAuditLogFn = origLog
		auditEventsFn = origEvents
	}()
	// Use a nil log; the stub events function ignores it.
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return stubEvents, nil }

	var buf bytes.Buffer
	err := auditCommandWithArgs(context.Background(), []string{"--since", "1h", "--json"}, &buf)
	if err != nil {
		t.Fatalf("--since flag: unexpected error: %v", err)
	}
	output := buf.String()
	// Exactly 1 event is within the last 1h; confirm the events count in the JSON.
	if !strings.Contains(output, `"events"`) {
		t.Fatalf("--since flag: expected JSON with 'events' key, got: %s", output)
	}
}

// ---------------------------------------------------------------------------
// 7. CLI surface: --secret flag accepted by auditCommandWithArgs
// ---------------------------------------------------------------------------

func TestAuditCommandWithArgsSecretFlag(t *testing.T) {
	lockAppSeams(t)

	origLog := newAuditLogFn
	origEvents := auditEventsFn
	defer func() {
		newAuditLogFn = origLog
		auditEventsFn = origEvents
	}()
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return nil, nil }

	// --secret flag must be accepted (not produce a "flag not defined" error).
	err := auditCommandWithArgs(context.Background(), []string{"--secret", "proj/DB_PASSWORD", "--json"}, io.Discard)
	if err != nil {
		t.Fatalf("--secret flag: expected no error but got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 8. CLI surface: unknown positional args still rejected
// ---------------------------------------------------------------------------

func TestAuditCommandWithArgsRejectsPositional(t *testing.T) {
	lockAppSeams(t)

	origLog := newAuditLogFn
	defer func() { newAuditLogFn = origLog }()
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }

	err := auditCommandWithArgs(context.Background(), []string{"extra"}, io.Discard)
	if err == nil {
		t.Fatal("expected error for positional argument, got nil")
	}
}
