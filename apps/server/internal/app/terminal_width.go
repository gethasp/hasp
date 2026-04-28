package app

import (
	"os"
	"strconv"
)

// terminalColumnsFn reports the current terminal width in columns. Returning
// 0 means "unknown" — callers must treat that as "do not clip" so we never
// truncate output in pipes, CI logs, or non-TTY contexts.
//
// Production reads $COLUMNS first (set by most shells; respects user-resized
// windows when exported) and falls back to 0. Tests stub this seam directly.
var terminalColumnsFn = defaultTerminalColumns

func defaultTerminalColumns() int {
	raw := os.Getenv("COLUMNS")
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// clipForTerminal returns value, possibly leading-ellipsis-clipped, so that
// `prefixLen + len(result)` fits in `columns`. If columns <= 0 (unknown
// terminal width) or the value already fits, the value is returned as-is.
//
// The clip uses a single Unicode ellipsis ("…", 1 column wide) on the left so
// the trailing portion (typically the filename) stays readable — exactly
// what users need when scanning a `hasp daemon status` table.
func clipForTerminal(value string, prefixLen, columns int) string {
	if columns <= 0 {
		return value
	}
	if prefixLen+len(value) <= columns {
		return value
	}
	budget := columns - prefixLen - 1 // 1 column for the ellipsis itself
	if budget <= 0 {
		return value
	}
	return "…" + value[len(value)-budget:]
}
