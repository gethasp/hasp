package redactor

// hasp-uhki: redactor markers are intentionally NOT length-preserving;
// `hasp help internals` documents that integrators must not assume byte
// offsets survive redaction. The one structural guarantee we DO promise
// is line-count preservation: no marker may contain '\n'. Lock that
// invariant here so a future marker change cannot silently break log
// shippers that rely on `wc -l` matching pre- vs post-redaction.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestRedactorMarkersAreSingleLine(t *testing.T) {
	val := bytes.Repeat([]byte("ABCDEFGH"), 8) // > minRedactLen, varied bytes
	for _, def := range buildForms(val) {
		if bytes.Contains(def.marker, []byte("\n")) {
			t.Fatalf("marker %q contains a newline; line-count preservation invariant broken", def.marker)
		}
		if !bytes.HasPrefix(def.marker, []byte("[REDACTED")) {
			t.Fatalf("marker %q does not start with [REDACTED — `hasp help internals` documents the [REDACTED…] family", def.marker)
		}
	}
}

func TestRedactorPreservesLineCountAcrossReplacement(t *testing.T) {
	// A multi-line input with one managed value must come out with the same
	// number of lines, even though the value's byte-length collapses.
	val := bytes.Repeat([]byte("X"), 4096)
	input := append([]byte("before\n"), val...)
	input = append(input, []byte("\nafter\n")...)

	got := Apply(input, []store.Item{{Name: "big", Value: val}})
	if !got.Redacted {
		t.Fatalf("expected redacted=true; got %+v", got)
	}
	if !bytes.Contains(got.Output, []byte("[REDACTED]")) {
		t.Fatalf("expected [REDACTED] marker in output; got %q", got.Output)
	}
	wantLines := strings.Count(string(input), "\n")
	gotLines := strings.Count(string(got.Output), "\n")
	if wantLines != gotLines {
		t.Fatalf("line count changed across redaction: want %d, got %d\ninput=%q\noutput=%q",
			wantLines, gotLines, input, got.Output)
	}
}
