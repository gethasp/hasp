package redactor

import (
	"bytes"
	"errors"
	"testing"
)

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write") }

func TestCoverageANSIHelpers(t *testing.T) {
	visible, indexMap, inProgress := stripANSI([]byte("a\x1b[31mb\x1b]title\x07c\x1b"))
	if string(visible) != "abc" || len(indexMap) != 3 || inProgress != 1 {
		t.Fatalf("stripANSI visible=%q index=%v inProgress=%d", visible, indexMap, inProgress)
	}
	cases := []struct {
		name string
		buf  []byte
		end  int
		ok   bool
	}{
		{"bare", []byte{0x1b}, 0, false},
		{"csi", []byte("\x1b[31m"), 5, true},
		{"csi incomplete", []byte("\x1b[31"), 0, false},
		{"osc bel", []byte("\x1b]title\x07"), 8, true},
		{"osc st", []byte("\x1b]title\x1b\\"), 9, true},
		{"osc bad esc", []byte("\x1b]title\x1bx"), 0, false},
		{"osc incomplete", []byte("\x1b]title"), 0, false},
		{"two char", []byte("\x1bM"), 2, true},
		{"unknown", []byte("\x1b?"), 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			end, ok := scanEscape(tc.buf, 0)
			if end != tc.end || ok != tc.ok {
				t.Fatalf("scanEscape got end=%d ok=%v", end, ok)
			}
		})
	}
}

func TestCoverageRedactorHelpers(t *testing.T) {
	if Needles(nil) != nil {
		t.Fatal("nil value should not produce needles")
	}
	if Needles([]byte("short")) != nil {
		t.Fatal("short value should not produce needles")
	}
	if got := encodeUnicodeEscape([]byte("A")); got != "\\u0041" {
		t.Fatalf("unicode escape %q", got)
	}
	if out, changed := replaceSpans([]byte("abc"), nil, []byte("x")); string(out) != "abc" || changed {
		t.Fatalf("empty needle replacement changed output: %q changed=%v", out, changed)
	}
}

func TestCoverageStreamingWriterBranches(t *testing.T) {
	if !ANSIAwareAvailable() {
		t.Fatal("ANSI-aware mode should be available")
	}
	sw := NewStreamingWriter(failWriter{}, nil)
	if n, err := sw.Write([]byte("abc")); err == nil || n != 0 {
		t.Fatalf("expected passthrough write error, n=%d err=%v", n, err)
	}

	var buf bytes.Buffer
	sw = &StreamingWriter{dst: &buf, pending: []byte("abcdef"), lookbackSize: 2, matched: map[string]bool{}}
	if err := sw.flushSafe(); err != nil {
		t.Fatalf("flushSafe no match: %v", err)
	}
	if buf.String() != "abcd" || string(sw.pending) != "ef" {
		t.Fatalf("no match buf=%q pending=%q", buf.String(), sw.pending)
	}

	buf.Reset()
	sw = &StreamingWriter{
		dst:          &buf,
		forms:        []needleForm{{needle: []byte("abc"), marker: []byte("X"), itemName: "a"}, {needle: []byte("bc"), marker: []byte("Y"), itemName: "b"}},
		pending:      []byte("abczz"),
		lookbackSize: 1,
		matched:      map[string]bool{},
	}
	if err := sw.flushSafe(); err != nil {
		t.Fatalf("flushSafe match: %v", err)
	}
	if !sw.redacted || !sw.matched["a"] || buf.String() == "" {
		t.Fatalf("match redacted=%v matched=%v buf=%q", sw.redacted, sw.matched, buf.String())
	}

	buf.Reset()
	sw = &StreamingWriter{
		dst:          &buf,
		forms:        []needleForm{{needle: []byte("SECRET"), marker: []byte("X"), itemName: "secret"}},
		pending:      []byte("xxSECRET"),
		lookbackSize: 3,
		matched:      map[string]bool{},
	}
	if err := sw.flushSafe(); err != nil {
		t.Fatalf("flushSafe straddle: %v", err)
	}
	if buf.String() != "xx" || string(sw.pending) != "SECRET" {
		t.Fatalf("straddle buf=%q pending=%q", buf.String(), sw.pending)
	}

	sw = &StreamingWriter{
		dst:          failWriter{},
		forms:        []needleForm{{needle: []byte("abc"), marker: []byte("X"), itemName: "a"}},
		pending:      []byte("abcdef"),
		lookbackSize: 1,
		matched:      map[string]bool{},
	}
	if err := sw.flushSafe(); err == nil {
		t.Fatal("expected flushSafe write error")
	}

	sw = &StreamingWriter{
		dst:          failWriter{},
		forms:        []needleForm{{needle: []byte("abc"), marker: []byte("X"), itemName: "a"}},
		pending:      []byte("abc"),
		lookbackSize: 1,
		matched:      map[string]bool{},
	}
	if err := sw.Flush(); err == nil {
		t.Fatal("expected Flush write error")
	}
	if got := sw.applyForms(nil); got != nil {
		t.Fatalf("applyForms empty = %q", got)
	}

	buf.Reset()
	sw = &StreamingWriter{
		dst:          &buf,
		forms:        []needleForm{{needle: []byte("abc"), marker: []byte("X"), itemName: "a"}},
		lookbackSize: 1,
		matched:      map[string]bool{},
	}
	if n, err := sw.Write([]byte("abcdef")); err != nil || n != 6 {
		t.Fatalf("Write flushSafe n=%d err=%v", n, err)
	}
	sw = &StreamingWriter{
		dst:          failWriter{},
		forms:        []needleForm{{needle: []byte("abc"), marker: []byte("X"), itemName: "a"}},
		lookbackSize: 1,
		matched:      map[string]bool{},
	}
	if n, err := sw.Write([]byte("abcdef")); err == nil || n != 0 {
		t.Fatalf("expected Write flush error, n=%d err=%v", n, err)
	}

	buf.Reset()
	sw = &StreamingWriter{
		dst:          &buf,
		forms:        []needleForm{{needle: []byte("abc"), marker: []byte("X"), itemName: "a"}},
		pending:      []byte("xxxabc"),
		lookbackSize: 3,
		matched:      map[string]bool{},
	}
	if err := sw.flushSafe(); err != nil {
		t.Fatalf("flushSafe match after safe boundary: %v", err)
	}
	if buf.String() != "xxx" {
		t.Fatalf("safe-boundary buf=%q", buf.String())
	}
}

func TestCoverageStreamingANSIBranches(t *testing.T) {
	var buf bytes.Buffer
	sw := &StreamingWriter{
		dst:          &buf,
		ansiAware:    true,
		forms:        []needleForm{{needle: []byte("SECRET"), marker: []byte("X"), itemName: "secret"}},
		pending:      []byte("abc"),
		lookbackSize: 3,
		matched:      map[string]bool{},
	}
	if err := sw.flushSafe(); err != nil {
		t.Fatalf("ansi short flushSafe: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("short ansi wrote %q", buf.String())
	}

	sw = &StreamingWriter{dst: &buf, ansiAware: true, pending: []byte("abcdef"), lookbackSize: 1, matched: map[string]bool{}}
	buf.Reset()
	if err := sw.flushSafeANSI(); err != nil {
		t.Fatalf("ansi no match: %v", err)
	}
	if buf.String() == "" {
		t.Fatal("expected ansi no-match output")
	}

	sw = &StreamingWriter{
		dst:          &buf,
		ansiAware:    true,
		forms:        []needleForm{{needle: []byte("SECRET"), marker: []byte("X"), itemName: "secret"}, {needle: []byte("CRET"), marker: []byte("Y"), itemName: "overlap"}},
		pending:      []byte("SE\x1b[31mCRETzz"),
		lookbackSize: 1,
		matched:      map[string]bool{},
	}
	buf.Reset()
	if err := sw.flushSafeANSI(); err != nil {
		t.Fatalf("ansi match: %v", err)
	}
	if !sw.redacted || !sw.matched["secret"] || buf.String() == "" {
		t.Fatalf("ansi match redacted=%v matched=%v buf=%q", sw.redacted, sw.matched, buf.String())
	}

	sw = &StreamingWriter{
		dst:          &buf,
		ansiAware:    true,
		forms:        []needleForm{{needle: []byte("SECRET"), marker: []byte("X"), itemName: "secret"}},
		pending:      []byte("xxSE\x1b[31mCRET"),
		lookbackSize: 3,
		matched:      map[string]bool{},
	}
	buf.Reset()
	if err := sw.flushSafeANSI(); err != nil {
		t.Fatalf("ansi straddle: %v", err)
	}
	if buf.String() != "xx" {
		t.Fatalf("ansi straddle buf=%q pending=%q", buf.String(), sw.pending)
	}

	sw = &StreamingWriter{
		dst:          failWriter{},
		ansiAware:    true,
		forms:        []needleForm{{needle: []byte("SECRET"), marker: []byte("X"), itemName: "secret"}},
		pending:      []byte("SECRETzz"),
		lookbackSize: 1,
		matched:      map[string]bool{},
	}
	if err := sw.flushSafeANSI(); err == nil {
		t.Fatal("expected ansi writer error")
	}

	buf.Reset()
	sw = &StreamingWriter{
		dst:          &buf,
		ansiAware:    true,
		forms:        []needleForm{{needle: []byte("SECRET"), marker: []byte("X"), itemName: "secret"}},
		pending:      []byte("xxxSECRET"),
		lookbackSize: 6,
		matched:      map[string]bool{},
	}
	if err := sw.flushSafeANSI(); err != nil {
		t.Fatalf("ansi match after safe boundary: %v", err)
	}
	if buf.String() != "xxx" {
		t.Fatalf("ansi safe-boundary buf=%q", buf.String())
	}

	buf.Reset()
	sw = &StreamingWriter{
		dst:          &buf,
		ansiAware:    true,
		forms:        []needleForm{{needle: []byte("SECRET"), marker: []byte("X"), itemName: "secret"}},
		pending:      []byte("SECRET"),
		lookbackSize: 3,
		matched:      map[string]bool{},
	}
	if err := sw.flushSafeANSI(); err != nil {
		t.Fatalf("ansi zero safe boundary: %v", err)
	}
	if buf.Len() != 0 || string(sw.pending) != "SECRET" {
		t.Fatalf("ansi zero safe buf=%q pending=%q", buf.String(), sw.pending)
	}

	sw = &StreamingWriter{matched: map[string]bool{}}
	if got := sw.applyFormsANSI(nil); got != nil {
		t.Fatalf("applyFormsANSI empty = %q", got)
	}
	if got := sw.applyFormsANSI([]byte("clean")); string(got) != "clean" {
		t.Fatalf("applyFormsANSI no match = %q", got)
	}
}
