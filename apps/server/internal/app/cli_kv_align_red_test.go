package app

// hasp-0kw3: cliWriteKeyValues currently pads every label to a fixed
// 24-char column. That looks ragged in two ways:
//   - When all labels are short (e.g. "PID", "Port"), trailing whitespace
//     puts the values 20+ spaces away from the keys.
//   - When any label is longer than 24 chars, that one row's value pushes
//     past the column and other rows misalign.
//
// The fix is per-block max-label-width: every value in a single block
// starts at the same column, and that column is exactly long-enough.

import (
	"bytes"
	"strings"
	"testing"
)

func TestCliWriteKeyValuesAlignsValueColumnAcrossPairs(t *testing.T) {
	var buf bytes.Buffer
	if err := cliWriteKeyValues(&buf, "Block",
		cliPair("PID", "42"),
		cliPair("Connections", "7"),
		cliPair("Status", "ok"),
	); err != nil {
		t.Fatalf("cliWriteKeyValues: %v", err)
	}

	cols := valueStartColumns(t, buf.String(), []string{"PID", "Connections", "Status"})
	for label, col := range cols {
		if col != cols["Connections"] {
			t.Fatalf("value column for %q=%d differs from %q=%d; want all aligned\nfull output:\n%s",
				label, col, "Connections", cols["Connections"], buf.String())
		}
	}
}

func TestCliWriteKeyValuesUsesTightColumnNotFixed24(t *testing.T) {
	var buf bytes.Buffer
	if err := cliWriteKeyValues(&buf, "Block",
		cliPair("PID", "42"),
		cliPair("Port", "8080"),
	); err != nil {
		t.Fatalf("cliWriteKeyValues: %v", err)
	}

	// With max label "Port" (4 chars), the value "42" should land within
	// the first ~10 columns of the row, not 24+ as the old %-24s padding
	// would force.
	cols := valueStartColumns(t, buf.String(), []string{"PID"})
	if cols["PID"] >= 24 {
		t.Fatalf("value start column for short-keys block = %d; want < 24 (column should be tight to longest label)\nfull output:\n%s", cols["PID"], buf.String())
	}
}

func TestCliWriteKeyValuesHandlesLabelLongerThan24(t *testing.T) {
	long := "A label that is definitely longer than twenty-four characters"
	var buf bytes.Buffer
	if err := cliWriteKeyValues(&buf, "Block",
		cliPair(long, "long-value"),
		cliPair("Short", "short-value"),
	); err != nil {
		t.Fatalf("cliWriteKeyValues: %v", err)
	}

	cols := valueStartColumns(t, buf.String(), []string{long, "Short"})
	if cols[long] != cols["Short"] {
		t.Fatalf("long label row value column %d != short label row value column %d; want both aligned\nfull output:\n%s",
			cols[long], cols["Short"], buf.String())
	}
}

// valueStartColumns finds the rune-column at which the value text starts on
// each labelled row. The renderer prefixes "  " then the label; we look for
// the label, skip past it, then count whitespace.
func valueStartColumns(t *testing.T, body string, labels []string) map[string]int {
	t.Helper()
	out := make(map[string]int, len(labels))
	for _, line := range strings.Split(body, "\n") {
		stripped := stripANSI(line)
		for _, label := range labels {
			idx := strings.Index(stripped, label)
			if idx == -1 {
				continue
			}
			pos := idx + len(label)
			for pos < len(stripped) && stripped[pos] == ' ' {
				pos++
			}
			if _, dup := out[label]; !dup {
				out[label] = pos
			}
		}
	}
	for _, label := range labels {
		if _, ok := out[label]; !ok {
			t.Fatalf("label %q not found in output:\n%s", label, body)
		}
	}
	return out
}

func stripANSI(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				i = j + 1
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
