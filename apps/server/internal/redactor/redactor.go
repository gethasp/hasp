package redactor

import (
	"bytes"
	"encoding/base64"
	"unicode/utf8"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

type Result struct {
	Output     []byte
	Redacted   bool
	Suppressed bool
}

func Apply(input []byte, items []store.Item) Result {
	if !utf8.Valid(input) {
		return Result{
			Output:     []byte("[REDACTED_OUTPUT_SUPPRESSED]\n"),
			Redacted:   true,
			Suppressed: true,
		}
	}
	output := append([]byte(nil), input...)
	redacted := false
	for _, item := range items {
		if len(item.Value) == 0 {
			continue
		}
		replaced, changed := replaceAll(output, item.Value, []byte("[REDACTED]"))
		output = replaced
		redacted = redacted || changed

		encoded := []byte(base64.StdEncoding.EncodeToString(item.Value))
		replaced, changed = replaceAll(output, encoded, []byte("[REDACTED_B64]"))
		output = replaced
		redacted = redacted || changed
	}

	if !utf8.Valid(output) {
		return Result{
			Output:     []byte("[REDACTED_OUTPUT_SUPPRESSED]\n"),
			Redacted:   redacted,
			Suppressed: true,
		}
	}
	return Result{Output: output, Redacted: redacted}
}

func replaceAll(input []byte, needle []byte, replacement []byte) ([]byte, bool) {
	if len(needle) == 0 || !bytes.Contains(input, needle) {
		return input, false
	}
	return bytes.ReplaceAll(input, needle, replacement), true
}
