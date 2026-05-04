package app

import (
	"io"
	"os"
	"strings"
)

// setupWriterSupportsUnicode reports whether out can safely render non-ASCII
// glyphs (✓ ✗ •). It returns false in any of these cases (hasp-41fc):
//   - NO_COLOR is set (the user opted out of stylised output)
//   - TERM=dumb (CI logs, basic shells)
//   - The locale is not UTF-8 (LC_ALL/LC_CTYPE/LANG don't contain "UTF-8")
//   - The writer is not a real terminal (pipes, files, buffers)
//
// Callers should pass the same io.Writer they actually print to so the
// decision tracks the real destination.
func setupWriterSupportsUnicode(out io.Writer) bool {
	if !setupWriterSupportsColor(out) {
		return false
	}
	return localeSupportsUTF8()
}

func localeSupportsUTF8() bool {
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if value := os.Getenv(key); value != "" {
			return localeStringIsUTF8(value)
		}
	}
	// No locale env vars set: most modern terminals default to UTF-8, but be
	// conservative and assume ASCII so users on legacy systems aren't
	// surprised by mojibake.
	return false
}

func localeStringIsUTF8(value string) bool {
	upper := strings.ToUpper(value)
	return strings.Contains(upper, "UTF-8") || strings.Contains(upper, "UTF8")
}

// cliGlyph returns unicode when the writer can render it, otherwise ascii.
// Use this for visible decorative glyphs so dumb terminals see "[ok]"
// instead of "â\x9c\x93".
func cliGlyph(out io.Writer, unicode, ascii string) string {
	if setupWriterSupportsUnicode(out) {
		return unicode
	}
	return ascii
}
