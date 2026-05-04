package app

import (
	"github.com/gethasp/hasp/apps/server/internal/app/ui"
)

// debugLogFn is the package-level seam for --debug output. Defaults to a
// no-op so the cost of leaving debug calls in the source is zero. The
// dispatcher replaces this with a stderr writer when gf.debug is set;
// tests replace it with a capture closure to assert on the messages.
// hasp-pjh4.
var debugLogFn = func(string, ...any) {}

// stdoutIsTTYFn tells `hasp run` whether to request PTY allocation from the
// runner so children that gate behaviour on isatty() see an interactive
// terminal. Defaults to ui.IsInteractiveWriter; tests override it so a
// bytes.Buffer-fed run can exercise the TTY codepath without standing up a
// real pty. hasp-ymuy.
var stdoutIsTTYFn = ui.IsInteractiveWriter
