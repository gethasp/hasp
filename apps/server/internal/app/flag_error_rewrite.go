package app

import (
	"errors"
	"strings"
)

// rewriteFlagDashForm rewrites references to single-dash long-form flags in
// flag-package error messages to the double-dash form users actually type
// (hasp-khcj). Go's stdlib reports "flag provided but not defined: -bad-flag"
// even when the user typed `--bad-flag`; this normaliser maps `-name` →
// `--name` whenever name has length > 1, so the echoed form matches the input.
//
// Single-character flags are left as-is (e.g. `-f`) because that is also a
// legitimate user-typed form.
func rewriteFlagDashForm(err error) error {
	if err == nil {
		return nil
	}
	original := err.Error()
	rewritten := rewriteFlagDashFormString(original)
	if rewritten == original {
		return err
	}
	return errors.New(rewritten)
}

// rewriteFlagDashFormString is exposed for unit testing; production callers
// should go through rewriteFlagDashForm.
func rewriteFlagDashFormString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		// Only rewrite a single dash that begins a flag token. We require the
		// preceding character to be a token boundary (start, space, or one of
		// the punctuation characters Go's flag package surrounds names with)
		// and the following character to look like a flag-name byte.
		if s[i] == '-' && (i == 0 || isFlagBoundary(s[i-1])) && i+1 < len(s) && s[i+1] != '-' && isFlagNameByte(s[i+1]) {
			j := i + 1
			for j < len(s) && isFlagNameByte(s[j]) {
				j++
			}
			name := s[i+1 : j]
			if len(name) > 1 {
				b.WriteString("--")
				b.WriteString(name)
				i = j
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func isFlagBoundary(c byte) bool {
	switch c {
	case ' ', ':', '(', '"', '\'', '\t', '=':
		return true
	}
	return false
}

func isFlagNameByte(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_'
}
