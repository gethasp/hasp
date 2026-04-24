package app

// RED TEAM tests for hasp-x05.3.2 "Add human timeline and table modes to audit".
//
// Contract pinned:
//   - Two new renderer helpers (package-internal, called directly in tests):
//       func auditRenderTimeline(events []audit.Event, w io.Writer) error
//       func auditRenderTable(events []audit.Event, w io.Writer) error
//   - auditCommandWithArgs accepts --format=timeline and --format=table flags.
//   - Timeline mode:  one line per event, chronological order.
//     Each line contains: timestamp (RFC3339 or HH:MM:SS), action (Event.Type),
//     reference (Details["reference"] or "-"), agent (Event.Actor),
//     and "BLOCKED" suffix when Details["blocked"] == true.
//   - Table mode: header row with columns: time, action, ref, agent, project, blocked;
//     followed by one data row per event.
//   - Redaction: plaintext secret values (Details keys containing "value") are
//     replaced by "[REDACTED]" in BOTH modes, exactly as redactAuditEvent does.
//   - Filter integration: --format=timeline (or table) + --secret must filter
//     before rendering.
//
// All tests MUST FAIL until the green team implements the feature.

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func makeHumanEvent(typ, actor string, details map[string]any, ts time.Time) audit.Event {
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
// 1. Timeline renderer: chronological ordering
// ---------------------------------------------------------------------------

func TestAuditTimelineChronologicalOrder(t *testing.T) {
	base := time.Date(2026, 4, 23, 14, 32, 0, 0, time.UTC)
	events := []audit.Event{
		makeHumanEvent(audit.EventRun, "agent-a", map[string]any{"reference": "proj/API_KEY"}, base.Add(2*time.Minute)),
		makeHumanEvent(audit.EventCapture, "agent-b", map[string]any{"reference": "proj/DB_PASS"}, base),
		makeHumanEvent(audit.EventInjectSafe, "agent-c", map[string]any{"reference": "proj/TOKEN"}, base.Add(1*time.Minute)),
	}

	var buf bytes.Buffer
	// auditRenderTimeline must exist and accept ([]audit.Event, io.Writer) → error.
	if err := auditRenderTimeline(events, &buf); err != nil {
		t.Fatalf("auditRenderTimeline: unexpected error: %v", err)
	}

	lines := nonEmptyLines(buf.String())
	if len(lines) != 3 {
		t.Fatalf("timeline: want 3 lines, got %d:\n%s", len(lines), buf.String())
	}

	// Earliest event (base, EventCapture) must appear on line 0.
	if !strings.Contains(lines[0], "capture") {
		t.Errorf("timeline: first line should contain earliest event (capture), got: %q", lines[0])
	}
	// Middle event (base+1m, EventInjectSafe) on line 1.
	if !strings.Contains(lines[1], "inject_safe") {
		t.Errorf("timeline: second line should contain inject_safe, got: %q", lines[1])
	}
	// Latest event (base+2m, EventRun) on line 2.
	if !strings.Contains(lines[2], "run") {
		t.Errorf("timeline: third line should contain run, got: %q", lines[2])
	}
}

// ---------------------------------------------------------------------------
// 2. Timeline renderer: required fields per line
// ---------------------------------------------------------------------------

func TestAuditTimelineLineFields(t *testing.T) {
	ts := time.Date(2026, 4, 23, 14, 32, 10, 0, time.UTC)
	events := []audit.Event{
		makeHumanEvent(audit.EventCapture, "claude-code", map[string]any{
			"reference": "proj/DB_PASS",
			"blocked":   false,
		}, ts),
	}

	var buf bytes.Buffer
	if err := auditRenderTimeline(events, &buf); err != nil {
		t.Fatalf("auditRenderTimeline: unexpected error: %v", err)
	}

	line := strings.TrimSpace(buf.String())
	// Must contain a timestamp substring (date portion or time portion).
	if !strings.Contains(line, "2026") && !strings.Contains(line, "14:32") {
		t.Errorf("timeline line: expected timestamp component, got: %q", line)
	}
	// Must contain event type (action label).
	if !strings.Contains(line, "capture") {
		t.Errorf("timeline line: expected action 'capture', got: %q", line)
	}
	// Must contain reference.
	if !strings.Contains(line, "proj/DB_PASS") {
		t.Errorf("timeline line: expected reference 'proj/DB_PASS', got: %q", line)
	}
	// Must contain actor/agent.
	if !strings.Contains(line, "claude-code") {
		t.Errorf("timeline line: expected agent 'claude-code', got: %q", line)
	}
	// Must NOT contain "BLOCKED" when blocked is false.
	if strings.Contains(line, "BLOCKED") {
		t.Errorf("timeline line: must not show BLOCKED for unblocked event, got: %q", line)
	}
}

// ---------------------------------------------------------------------------
// 3. Timeline renderer: BLOCKED indicator
// ---------------------------------------------------------------------------

func TestAuditTimelineBlockedIndicator(t *testing.T) {
	ts := time.Date(2026, 4, 23, 14, 32, 10, 0, time.UTC)
	events := []audit.Event{
		makeHumanEvent(audit.EventRepoBlock, "guard", map[string]any{
			"reference": "proj/SECRET",
			"blocked":   true,
		}, ts),
	}

	var buf bytes.Buffer
	if err := auditRenderTimeline(events, &buf); err != nil {
		t.Fatalf("auditRenderTimeline: unexpected error: %v", err)
	}

	line := strings.TrimSpace(buf.String())
	if !strings.Contains(line, "BLOCKED") {
		t.Errorf("timeline line: expected BLOCKED suffix for blocked event, got: %q", line)
	}
}

// ---------------------------------------------------------------------------
// 4. Table renderer: header columns
// ---------------------------------------------------------------------------

func TestAuditTableHeaderColumns(t *testing.T) {
	events := []audit.Event{
		makeHumanEvent(audit.EventRun, "agent-x", map[string]any{}, time.Now().UTC()),
	}

	var buf bytes.Buffer
	// auditRenderTable must exist and accept ([]audit.Event, io.Writer) → error.
	if err := auditRenderTable(events, &buf); err != nil {
		t.Fatalf("auditRenderTable: unexpected error: %v", err)
	}

	output := strings.ToLower(buf.String())
	lines := nonEmptyLines(output)
	if len(lines) == 0 {
		t.Fatal("table: expected at least 1 line (header), got empty output")
	}

	header := lines[0]
	requiredCols := []string{"time", "action", "ref", "agent", "project", "blocked"}
	for _, col := range requiredCols {
		if !strings.Contains(header, col) {
			t.Errorf("table header: missing column %q in header line: %q", col, header)
		}
	}
}

// ---------------------------------------------------------------------------
// 5. Table renderer: data rows
// ---------------------------------------------------------------------------

func TestAuditTableDataRows(t *testing.T) {
	ts := time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)
	events := []audit.Event{
		makeHumanEvent(audit.EventCapture, "agent-z", map[string]any{
			"reference":    "proj/API_KEY",
			"project_root": "/home/user/myapp",
		}, ts),
		makeHumanEvent(audit.EventRun, "agent-w", map[string]any{
			"reference":    "proj/DB_PASS",
			"project_root": "/home/user/other",
		}, ts.Add(1*time.Minute)),
	}

	var buf bytes.Buffer
	if err := auditRenderTable(events, &buf); err != nil {
		t.Fatalf("auditRenderTable: unexpected error: %v", err)
	}

	lines := nonEmptyLines(buf.String())
	// Expect header + 2 data rows = at least 3 lines.
	if len(lines) < 3 {
		t.Fatalf("table: want at least 3 lines (header + 2 rows), got %d:\n%s", len(lines), buf.String())
	}

	combined := buf.String()
	if !strings.Contains(combined, "capture") {
		t.Errorf("table: expected 'capture' action in output, got:\n%s", combined)
	}
	if !strings.Contains(combined, "run") {
		t.Errorf("table: expected 'run' action in output, got:\n%s", combined)
	}
	if !strings.Contains(combined, "agent-z") {
		t.Errorf("table: expected agent 'agent-z' in output, got:\n%s", combined)
	}
}

// ---------------------------------------------------------------------------
// 6. Redaction: timeline mode must NOT leak plaintext secret values
// ---------------------------------------------------------------------------

func TestAuditTimelineRedactsSecretValues(t *testing.T) {
	ts := time.Now().UTC()
	const plaintextSecret = "super-secret-plaintext-value-12345"
	events := []audit.Event{
		makeHumanEvent(audit.EventCapture, "agent", map[string]any{
			"reference": "proj/MY_SECRET",
			"value":     plaintextSecret, // this field must be redacted
		}, ts),
	}

	var buf bytes.Buffer
	if err := auditRenderTimeline(events, &buf); err != nil {
		t.Fatalf("auditRenderTimeline: unexpected error: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, plaintextSecret) {
		t.Errorf("timeline: plaintext secret value leaked in output:\n%s", output)
	}
	// Confirm the redaction placeholder appears instead.
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("timeline: expected [REDACTED] placeholder, got:\n%s", output)
	}
}

// ---------------------------------------------------------------------------
// 7. Redaction: table mode must NOT leak plaintext secret values
// ---------------------------------------------------------------------------

func TestAuditTableRedactsSecretValues(t *testing.T) {
	ts := time.Now().UTC()
	const plaintextSecret = "another-secret-do-not-expose-99"
	events := []audit.Event{
		makeHumanEvent(audit.EventCapture, "agent", map[string]any{
			"reference":    "proj/CRED",
			"secret_value": plaintextSecret, // this key also triggers redaction
		}, ts),
	}

	var buf bytes.Buffer
	if err := auditRenderTable(events, &buf); err != nil {
		t.Fatalf("auditRenderTable: unexpected error: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, plaintextSecret) {
		t.Errorf("table: plaintext secret value leaked in output:\n%s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("table: expected [REDACTED] placeholder, got:\n%s", output)
	}
}

// ---------------------------------------------------------------------------
// 8. Filter + timeline: --format=timeline --secret must filter before render
// ---------------------------------------------------------------------------

func TestAuditCommandTimelineWithSecretFilter(t *testing.T) {
	lockAppSeams(t)

	base := time.Now().UTC()
	allEvents := []audit.Event{
		makeHumanEvent(audit.EventInjectSafe, "agent-a", map[string]any{"reference": "proj/KEEP_ME"}, base),
		makeHumanEvent(audit.EventInjectSafe, "agent-b", map[string]any{"reference": "proj/SKIP_ME"}, base.Add(time.Second)),
		makeHumanEvent(audit.EventCapture, "agent-c", map[string]any{"reference": "proj/KEEP_ME"}, base.Add(2*time.Second)),
	}

	origLog := newAuditLogFn
	origEvents := auditEventsFn
	defer func() {
		newAuditLogFn = origLog
		auditEventsFn = origEvents
	}()
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return allEvents, nil }

	var buf bytes.Buffer
	err := auditCommandWithArgs([]string{"--format", "timeline", "--secret", "proj/KEEP_ME"}, &buf)
	if err != nil {
		t.Fatalf("--format=timeline --secret: unexpected error: %v", err)
	}

	output := buf.String()
	// Only events for proj/KEEP_ME should appear.
	if strings.Contains(output, "proj/SKIP_ME") {
		t.Errorf("--format=timeline --secret filter: proj/SKIP_ME leaked into output:\n%s", output)
	}
	// Both KEEP_ME events should be present.
	lines := nonEmptyLines(output)
	if len(lines) < 2 {
		t.Errorf("--format=timeline --secret filter: expected 2 lines for proj/KEEP_ME, got %d:\n%s", len(lines), output)
	}
}

// ---------------------------------------------------------------------------
// 9. Filter + table: --format=table --secret must filter before render
// ---------------------------------------------------------------------------

func TestAuditCommandTableWithSecretFilter(t *testing.T) {
	lockAppSeams(t)

	base := time.Now().UTC()
	allEvents := []audit.Event{
		makeHumanEvent(audit.EventRun, "agent-a", map[string]any{"reference": "proj/TARGET"}, base),
		makeHumanEvent(audit.EventRun, "agent-b", map[string]any{"reference": "proj/OTHER"}, base.Add(time.Second)),
	}

	origLog := newAuditLogFn
	origEvents := auditEventsFn
	defer func() {
		newAuditLogFn = origLog
		auditEventsFn = origEvents
	}()
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return allEvents, nil }

	var buf bytes.Buffer
	err := auditCommandWithArgs([]string{"--format", "table", "--secret", "proj/TARGET"}, &buf)
	if err != nil {
		t.Fatalf("--format=table --secret: unexpected error: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "proj/OTHER") {
		t.Errorf("--format=table --secret filter: proj/OTHER leaked into output:\n%s", output)
	}
	if !strings.Contains(output, "proj/TARGET") {
		t.Errorf("--format=table --secret filter: proj/TARGET missing from output:\n%s", output)
	}
}

// ---------------------------------------------------------------------------
// 10. CLI flag surface: --format flag accepted (not a "flag not defined" error)
// ---------------------------------------------------------------------------

func TestAuditCommandAcceptsFormatFlag(t *testing.T) {
	lockAppSeams(t)

	origLog := newAuditLogFn
	origEvents := auditEventsFn
	defer func() {
		newAuditLogFn = origLog
		auditEventsFn = origEvents
	}()
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return nil, nil }

	for _, fmt := range []string{"timeline", "table"} {
		var buf bytes.Buffer
		err := auditCommandWithArgs([]string{"--format", fmt}, &buf)
		if err != nil {
			t.Errorf("--format=%s: unexpected error: %v", fmt, err)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func nonEmptyLines(s string) []string {
	all := strings.Split(s, "\n")
	out := make([]string, 0, len(all))
	for _, l := range all {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
