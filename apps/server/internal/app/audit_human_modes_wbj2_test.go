package app

// hasp-wbj2: timeline alignment must survive variable-width action and
// reference columns. The previous %-16s/%-30s format silently overflowed
// when types like "secret.get.plaintext_grant_used" or long references
// pushed the agent column past its anchor.

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

// columnAt returns the byte index where the given substring begins on the
// first line of the rendered output. Returns -1 if not found.
func columnAt(line, sub string) int {
	return strings.Index(line, sub)
}

func TestAuditTimelineColumnsAlignAcrossWidths(t *testing.T) {
	base := time.Date(2026, 4, 23, 14, 32, 10, 0, time.UTC)
	events := []audit.Event{
		// Short action, short ref: agent should anchor at column N.
		makeHumanEvent(audit.EventRun, "agent-aaaa", map[string]any{
			"reference": "proj/A",
		}, base),
		// Long action, long ref: same agent must anchor at the same column.
		makeHumanEvent("secret.get.plaintext_grant_used", "agent-aaaa", map[string]any{
			"reference": "very/long/project/path/to/some/deep/secret/NAME_THAT_KEEPS_GOING",
		}, base.Add(time.Second)),
	}

	var buf bytes.Buffer
	if err := auditRenderTimeline(events, &buf); err != nil {
		t.Fatalf("auditRenderTimeline: %v", err)
	}
	lines := nonEmptyLines(buf.String())
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d:\n%s", len(lines), buf.String())
	}

	col0 := columnAt(lines[0], "agent-aaaa")
	col1 := columnAt(lines[1], "agent-aaaa")
	if col0 < 0 || col1 < 0 {
		t.Fatalf("agent name missing on a line:\n%q\n%q", lines[0], lines[1])
	}
	if col0 != col1 {
		t.Fatalf("agent column drifted between rows: %d vs %d\n%q\n%q",
			col0, col1, lines[0], lines[1])
	}
}
