package app

// RED tests for hasp-xbdr — color the session-state badge in
// `hasp session list`. Contract pinned:
//
//   - When ui.ColorOptions allow color, each session row carries a state
//     badge: green "[active]" when ExpiresAt is in the future, red
//     "[expired]" when ExpiresAt is in the past or zero.
//   - When the writer is non-interactive (bytes.Buffer in tests) the badge
//     still appears but as plain text — no ANSI sequences.
//   - The header line ("ID HOST PROJECT ...") and the "No active sessions."
//     fallback are preserved so machine-readable post-processing stays
//     intact.

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func TestSessionListShowsActiveBadgeGreenWhenColored(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	sessions := []runtime.SessionView{
		{
			ID:          "sess-1",
			HostLabel:   "host-a",
			ProjectRoot: "/tmp/repo",
			ExpiresAt:   time.Now().Add(15 * time.Minute),
			LastSeenAt:  time.Now(),
		},
	}
	var buf bytes.Buffer
	if err := renderSessionListWithColor(&buf, sessions, ui.ColorOptions{Interactive: true}); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "active") {
		t.Fatalf("expected 'active' badge, got %q", out)
	}
	if !strings.Contains(out, "\x1b[32m") {
		t.Fatalf("expected green ANSI sequence for active session, got %q", out)
	}
}

func TestSessionListShowsExpiredBadgeRedWhenColored(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	sessions := []runtime.SessionView{
		{
			ID:          "sess-2",
			HostLabel:   "host-b",
			ProjectRoot: "/tmp/repo",
			ExpiresAt:   time.Now().Add(-15 * time.Minute),
			LastSeenAt:  time.Now().Add(-30 * time.Minute),
		},
	}
	var buf bytes.Buffer
	if err := renderSessionListWithColor(&buf, sessions, ui.ColorOptions{Interactive: true}); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "expired") {
		t.Fatalf("expected 'expired' badge, got %q", out)
	}
	if !strings.Contains(out, "\x1b[31m") {
		t.Fatalf("expected red ANSI sequence for expired session, got %q", out)
	}
}

func TestSessionListPlainBadgeWhenNonInteractive(t *testing.T) {
	sessions := []runtime.SessionView{
		{
			ID:         "sess-3",
			HostLabel:  "host-c",
			ExpiresAt:  time.Now().Add(15 * time.Minute),
			LastSeenAt: time.Now(),
		},
	}
	var buf bytes.Buffer
	if err := renderSessionListWithColor(&buf, sessions, ui.ColorOptions{Interactive: false}); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "active") {
		t.Fatalf("expected 'active' label even in plain mode, got %q", out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Fatalf("expected no ANSI sequences in non-interactive mode, got %q", out)
	}
}

func TestSessionListPreservesHeaderAndEmptyFallback(t *testing.T) {
	var buf bytes.Buffer
	if err := renderSessionListWithColor(&buf, nil, ui.ColorOptions{Interactive: true}); err != nil {
		t.Fatalf("render empty: %v", err)
	}
	if !strings.Contains(buf.String(), "No active sessions.") {
		t.Fatalf("expected empty fallback preserved, got %q", buf.String())
	}

	sessions := []runtime.SessionView{
		{ID: "sess-4", HostLabel: "host-d", ExpiresAt: time.Now().Add(time.Hour)},
	}
	buf.Reset()
	if err := renderSessionListWithColor(&buf, sessions, ui.ColorOptions{Interactive: false}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), "ID") || !strings.Contains(buf.String(), "EXPIRES") {
		t.Fatalf("expected header columns preserved, got %q", buf.String())
	}
}
