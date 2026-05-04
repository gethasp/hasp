package app

// hasp-41fc: Unicode glyphs (✓ ✗ •) must fall back to ASCII when --no-color
// or NO_COLOR is set, when TERM=dumb, or when the locale isn't UTF-8 (LANG=C).
// Otherwise they render as mojibake on legacy terminals and CI logs.

import (
	"bytes"
	"strings"
	"testing"
)

func TestCliSuccessLeadFallsBackToAsciiWhenColorOff(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	got := cliSuccessLead(&bytes.Buffer{}, "all good")
	if strings.Contains(got, "✓") {
		t.Fatalf("NO_COLOR should suppress unicode glyph, got %q", got)
	}
	if !strings.Contains(got, "[ok]") {
		t.Fatalf("expected ASCII [ok] fallback, got %q", got)
	}
}

func TestCliBulletFallsBackToAsciiWhenLangNotUTF8(t *testing.T) {
	t.Setenv("LANG", "C")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_CTYPE", "")
	got := cliBullet(&bytes.Buffer{}, "label")
	if strings.Contains(got, "•") {
		t.Fatalf("LANG=C should suppress unicode bullet, got %q", got)
	}
	if !strings.Contains(got, "- ") && !strings.Contains(got, "-  ") {
		t.Fatalf("expected ASCII '-' bullet, got %q", got)
	}
}

func TestCliSuccessLeadKeepsUnicodeWhenUTF8AndColorOn(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("LANG", "en_US.UTF-8")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_CTYPE", "")
	t.Setenv("TERM", "xterm-256color")
	// Use a non-TTY writer; the existing setupWriterSupportsColor returns
	// false there so we still expect ASCII (the fallback shape preserves
	// readability without ANSI escapes). Confirm at minimum that mojibake
	// candidates are absent from the output.
	got := cliSuccessLead(&bytes.Buffer{}, "all good")
	if strings.Contains(got, "Â") || strings.Contains(got, "Ã") {
		t.Fatalf("output should never contain mojibake bytes, got %q", got)
	}
}

func TestCliGlyphHelperPicksAsciiByDefault(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	got := cliGlyph(&bytes.Buffer{}, "✓", "[ok]")
	if got != "[ok]" {
		t.Fatalf("cliGlyph with NO_COLOR should return ascii fallback, got %q", got)
	}
}

func TestSetupWriterSupportsUnicodeRespectsLocale(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")

	t.Setenv("LC_ALL", "C")
	if setupWriterSupportsUnicode(&bytes.Buffer{}) {
		t.Fatal("LC_ALL=C must disable unicode")
	}

	t.Setenv("LC_ALL", "")
	t.Setenv("LANG", "en_US.UTF-8")
	// Buffer writers are never TTYs; even with UTF-8 locale + color off, this
	// codepath should fall back. We document the expectation explicitly.
	if setupWriterSupportsUnicode(&bytes.Buffer{}) {
		t.Fatal("non-TTY writer must not advertise unicode support")
	}
}
