package ui

// RED tests for hasp-ayc2 — TTY-aware color rendering. Migrated to package
// ui under hasp-vpbf (Stage 1 of hasp-mgz5).
//
//   - IsInteractiveWriter returns false for non-*os.File writers (bytes.Buffer
//     in tests is the canonical non-tty case).
//   - Colorize(text, color, opts) returns plain text when (a) the writer is
//     not interactive, (b) opts.Disable is set, or (c) NO_COLOR is set.
//   - When the writer is interactive and color is allowed, Colorize returns
//     ANSI-wrapped text.
//   - colorPalette exposes the canonical security-tool palette: ok=green,
//     warn=yellow, deny=red. Other names fall back to plain.
//   - ShouldPage returns true only when stdout is interactive, --no-pager
//     is unset, and the line count exceeds the threshold.

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestIsInteractiveWriterFalseForByteBuffer(t *testing.T) {
	if IsInteractiveWriter(&bytes.Buffer{}) {
		t.Fatal("expected bytes.Buffer to be reported as non-interactive")
	}
}

func TestIsInteractiveWriterHandlesFileStatCases(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open dev null: %v", err)
	}
	defer devNull.Close()
	if !IsInteractiveWriter(devNull) {
		t.Fatal("expected os.DevNull to report as a character device")
	}

	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if err := closed.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	if IsInteractiveWriter(closed) {
		t.Fatal("closed file should not be interactive")
	}
}

func TestColorizeReturnsPlainForNonInteractive(t *testing.T) {
	got := Colorize("ok", ColorOK, ColorOptions{Interactive: false})
	if got != "ok" {
		t.Fatalf("expected plain text on non-interactive, got %q", got)
	}
}

func TestColorizeReturnsPlainWhenDisabled(t *testing.T) {
	got := Colorize("ok", ColorOK, ColorOptions{Interactive: true, Disable: true})
	if got != "ok" {
		t.Fatalf("expected plain text when Disable=true, got %q", got)
	}
}

func TestColorizeRespectsNoColorEnv(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	got := Colorize("ok", ColorOK, ColorOptions{Interactive: true})
	if got != "ok" {
		t.Fatalf("expected plain text when NO_COLOR is set, got %q", got)
	}
}

func TestColorizeWrapsWhenInteractiveAndAllowed(t *testing.T) {
	os.Unsetenv("NO_COLOR")
	got := Colorize("ok", ColorOK, ColorOptions{Interactive: true})
	if !strings.Contains(got, "\x1b[") {
		t.Fatalf("expected ANSI escape in output, got %q", got)
	}
	if !strings.Contains(got, "ok") {
		t.Fatalf("expected payload text in output, got %q", got)
	}
}

func TestColorPaletteSecurityRoles(t *testing.T) {
	for _, role := range []string{ColorOK, ColorWarn, ColorDeny} {
		got := Colorize("x", role, ColorOptions{Interactive: true})
		if got == "x" {
			t.Fatalf("expected role %q to wrap text, got plain", role)
		}
	}
	if got := Colorize("x", "rainbow", ColorOptions{Interactive: true}); got != "x" {
		t.Fatalf("expected unknown role to produce plain text, got %q", got)
	}
}

func TestShouldPageOnlyWhenInteractiveAndOverThreshold(t *testing.T) {
	if ShouldPage(PagerOptions{Interactive: false, Lines: 1000, Threshold: 25}) {
		t.Fatal("non-interactive should never page")
	}
	if ShouldPage(PagerOptions{Interactive: true, Disable: true, Lines: 1000, Threshold: 25}) {
		t.Fatal("Disable=true should suppress paging")
	}
	if ShouldPage(PagerOptions{Interactive: true, Lines: 10, Threshold: 25}) {
		t.Fatal("under threshold should not page")
	}
	if !ShouldPage(PagerOptions{Interactive: true, Lines: 100, Threshold: 25}) {
		t.Fatal("over threshold should page")
	}
	if ShouldPage(PagerOptions{Interactive: true, Lines: 25}) {
		t.Fatal("default threshold should not page at 25 lines")
	}
	if !ShouldPage(PagerOptions{Interactive: true, Lines: 26}) {
		t.Fatal("default threshold should page over 25 lines")
	}
}
