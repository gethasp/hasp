package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

// emitDeprecationWarning prints a deprecation notice to stderr unless the
// caller has asked for a quiet/scripted run (hasp-y78u). The notice is
// suppressed when:
//
//   - --quiet (or HASP_QUIET, mapped onto globalFlags.quiet) is set, OR
//   - HASP_NO_DEPRECATION is set to a truthy value (1, true, yes, on)
//
// stderr nil is treated as "no destination" and is a no-op.
func emitDeprecationWarning(ctx context.Context, stderr io.Writer, format string, a ...any) {
	if stderr == nil {
		return
	}
	if globalFlagsFromContext(ctx).quiet {
		return
	}
	if deprecationOptOutFromEnv(os.Getenv("HASP_NO_DEPRECATION")) {
		return
	}
	fmt.Fprintf(stderr, format, a...)
}

// deprecationOptOutFromEnv parses the HASP_NO_DEPRECATION env var. Only the
// canonical truthy spellings opt out so an accidental "0", "false", or empty
// value still prints.
func deprecationOptOutFromEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
