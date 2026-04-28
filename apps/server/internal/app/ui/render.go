// Package ui holds the leaf rendering primitives shared across the cli/runtime
// dispatch in package app: the color palette, the colorOptions/pagerOptions
// shapes, and the small interactive-writer detector. Keeping these in their
// own package lets the bigger surfaces (secret_commands, runtime_commands,
// doctor, …) move out of the internal/app monolith in later stages without
// circular imports through render helpers. hasp-vpbf (Stage 1 of hasp-mgz5).
package ui

import (
	"io"
	"os"
)

// Color role names for the security-tool palette. Each role maps to a single
// ANSI sequence; unknown roles fall back to plain text rather than producing
// garbage on a terminal that doesn't recognise them.
const (
	ColorOK   = "ok"   // green — successful, healthy, granted
	ColorWarn = "warn" // yellow — degraded, deprecated, advisory
	ColorDeny = "deny" // red — denied, failed, blocked
)

var ansiPalette = map[string]string{
	ColorOK:   "\x1b[32m",
	ColorWarn: "\x1b[33m",
	ColorDeny: "\x1b[31m",
}

const ansiReset = "\x1b[0m"

// ColorOptions controls how Colorize and the cli renderers emit ANSI escapes.
type ColorOptions struct {
	// Interactive is true when the destination writer is a TTY. Callers
	// derive this from IsInteractiveWriter so tests can flip the flag
	// without standing up a fake terminal.
	Interactive bool
	// Disable forces plain output even when interactive — set when the user
	// passes --no-color or globalFlags.noColor is true.
	Disable bool
	// Quiet suppresses non-essential informational lines (stage headers and
	// success-lead lines) when the user passes --quiet. Primary output
	// (secret names, key-value pairs, bullet rows) is preserved unchanged.
	Quiet bool
	// Verbose surfaces opt-in detail lines (created-at timestamps, full
	// absolute paths, extra columns) when the user passes --verbose. The
	// default-false output stays identical to pre-flag rendering so
	// scripts that grep human output don't suddenly see new fields.
	Verbose bool
}

// Colorize wraps text in the ANSI sequence for the given role, but only when
// (a) the writer is interactive, (b) opts.Disable is unset, and (c) NO_COLOR
// is unset (per the well-known no-color.org convention). Unknown roles fall
// back to plain text.
func Colorize(text, role string, opts ColorOptions) string {
	if !opts.Interactive || opts.Disable {
		return text
	}
	if os.Getenv("NO_COLOR") != "" {
		return text
	}
	seq, ok := ansiPalette[role]
	if !ok {
		return text
	}
	return seq + text + ansiReset
}

// IsInteractiveWriter reports whether w is a terminal-backed *os.File. The
// runtime check is small on purpose — the package already calls os.Stdout
// from the dispatcher, so callers thread that through. Non-*os.File writers
// (bytes.Buffer in tests, pipes, files) are always non-interactive.
func IsInteractiveWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// PagerOptions controls whether output should be piped through $PAGER.
type PagerOptions struct {
	Interactive bool
	Disable     bool
	Lines       int
	Threshold   int
}

// ShouldPage returns true when the caller should pipe its output through
// $PAGER. Paging only kicks in for interactive sessions over the threshold;
// --no-pager (opts.Disable) suppresses paging unconditionally.
func ShouldPage(opts PagerOptions) bool {
	if !opts.Interactive || opts.Disable {
		return false
	}
	if opts.Threshold <= 0 {
		opts.Threshold = 25
	}
	return opts.Lines > opts.Threshold
}
