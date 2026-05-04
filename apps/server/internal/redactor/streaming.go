package redactor

import (
	"bytes"
	"io"
	"sort"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// Stats mirrors the redaction summary fields of Result, but accumulates across
// multiple Write calls so callers can collect post-stream metrics.
type Stats struct {
	Redacted     bool
	MatchedItems []string // sorted, deduplicated item names with at least one match
}

// StreamingWriter wraps an io.Writer and redacts managed-secret values on the
// fly. It holds a lookback buffer of (maxNeedleLen - 1) bytes of original
// input so a token straddling a Write boundary is still correctly redacted.
// When no items are provided the writer is a zero-copy passthrough with no
// buffering at all.
//
// Call Flush() after the last Write to drain remaining buffered bytes. Stats()
// returns aggregated redaction statistics across all Write+Flush calls.
type StreamingWriter struct {
	dst          io.Writer
	forms        []needleForm    // all (needle, marker, itemName) tuples
	pending      []byte          // accumulated original bytes not yet emitted
	lookbackSize int             // maxNeedleLen - 1
	maxNeedleLen int             // max len across all needle forms
	matched      map[string]bool // item names that produced at least one match
	redacted     bool
	// ansiAware enables ANSI-escape-aware matching: needles are scanned
	// against the visible-byte projection of pending (with ANSI sequences
	// stripped) but matched spans are replaced in the original buffer so
	// non-secret formatting passes through unchanged. hasp-ab5d.
	ansiAware bool
}

type needleForm struct {
	needle   []byte
	marker   []byte
	itemName string
}

// ANSIAwareAvailable reports whether this build offers the ANSI-aware
// streaming-redaction mode. Always true; the function exists so doctor and
// other diagnostic surfaces can advertise the capability without importing
// the streaming type. hasp-ab5d.
func ANSIAwareAvailable() bool { return true }

// NewStreamingWriterANSIAware is identical to NewStreamingWriter except the
// returned writer matches needles against the visible-byte projection of the
// pending buffer (ANSI escape sequences are skipped during matching) so that
// a secret split across colour/style escapes — e.g. `AKIA\x1b[1mTEST\x1b[0m`
// against `AKIATEST` — is still redacted. Non-secret escapes pass through
// unchanged. hasp-ab5d.
func NewStreamingWriterANSIAware(dst io.Writer, items []store.Item) *StreamingWriter {
	sw := NewStreamingWriter(dst, items)
	sw.ansiAware = true
	return sw
}

// NewStreamingWriter constructs a StreamingWriter that writes redacted output
// to dst. Items shorter than minRedactLen are silently skipped, matching
// Apply's behaviour. If items is empty (or all are sub-threshold), the writer
// is a zero-buffering passthrough.
func NewStreamingWriter(dst io.Writer, items []store.Item) *StreamingWriter {
	var forms []needleForm
	maxNeedle := 0
	for _, it := range items {
		if len(it.Value) == 0 || len(it.Value) < minRedactLen {
			continue
		}
		defs := buildForms(it.Value)
		for _, d := range defs {
			forms = append(forms, needleForm{
				needle:   d.needle,
				marker:   d.marker,
				itemName: it.Name,
			})
			if len(d.needle) > maxNeedle {
				maxNeedle = len(d.needle)
			}
		}
	}

	lookbackSize := 0
	if maxNeedle > 0 {
		lookbackSize = maxNeedle - 1
	}

	return &StreamingWriter{
		dst:          dst,
		forms:        forms,
		lookbackSize: lookbackSize,
		maxNeedleLen: maxNeedle,
		matched:      make(map[string]bool),
	}
}

// Write implements io.Writer. Bytes are appended to the internal pending
// buffer. When pending exceeds lookbackSize bytes, we run redaction on the
// full pending buffer and emit the redacted bytes corresponding to the safe
// original prefix (pending[:len(pending)-lookbackSize]), retaining the
// last lookbackSize original bytes for the next round.
//
// The safe-prefix boundary in the REDACTED output is computed via offset
// tracking: we accumulate the length expansion caused by marker substitutions
// and find exactly which byte in the redacted output corresponds to the
// original position lookbackSize bytes from the end of pending.
func (sw *StreamingWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := len(p)

	if sw.lookbackSize == 0 {
		// Fast path: zero-copy passthrough.
		if _, err := sw.dst.Write(p); err != nil {
			return 0, err
		}
		return total, nil
	}

	sw.pending = append(sw.pending, p...)

	if len(sw.pending) > sw.lookbackSize {
		if err := sw.flushSafe(); err != nil {
			return 0, err
		}
	}

	return total, nil
}

// flushSafe runs redaction on all of pending, emits the redacted bytes that
// correspond to the original safe prefix (all but the last lookbackSize
// original bytes), and retains the last lookbackSize original bytes.
func (sw *StreamingWriter) flushSafe() error {
	if sw.ansiAware {
		return sw.flushSafeANSI()
	}
	safeOrigLen := len(sw.pending) - sw.lookbackSize

	// Find all needle match positions in pending before running replacement.
	// We need this to map original position safeOrigLen to its position in the
	// redacted output so we emit exactly the right number of bytes.
	type match struct {
		start     int // original start (inclusive)
		end       int // original end (exclusive)
		markerLen int
	}
	var matches []match
	for _, f := range sw.forms {
		// Scan all occurrences of this needle in pending.
		src := sw.pending
		offset := 0
		for {
			idx := bytes.Index(src, f.needle)
			if idx < 0 {
				break
			}
			absStart := offset + idx
			absEnd := absStart + len(f.needle)
			matches = append(matches, match{
				start:     absStart,
				end:       absEnd,
				markerLen: len(f.marker),
			})
			// Advance past the match.
			offset = absEnd
			src = sw.pending[offset:]
		}
	}

	// Sort matches by start position so we can iterate left-to-right.
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].start < matches[j].start
	})

	// Apply redaction on the full pending buffer.
	redacted := sw.applyForms(sw.pending)

	// Walk through matches left-to-right to find the safe-to-emit boundary in
	// the redacted output. We accumulate redacted bytes from matches that are
	// fully within the safe original prefix. For a match that straddles the
	// safe/retained boundary we stop BEFORE it: we cannot emit any bytes of
	// its original span because the retained bytes would otherwise be output
	// again unredacted in the next round. Instead, we move the safe boundary
	// back to just before that straddling match, ensuring the full needle is
	// available in the next round's retained buffer.
	redactedOffset := 0
	origCursor := 0
	actualSafeOrigLen := safeOrigLen // may be reduced if a match straddles
	for _, m := range matches {
		// Skip matches already consumed (overlapping with a prior match).
		if m.start < origCursor {
			continue
		}
		if m.start >= actualSafeOrigLen {
			break
		}
		if m.end <= actualSafeOrigLen {
			// Fully within safe region: account for the replacement.
			redactedOffset += (m.start - origCursor) // plain bytes before match
			redactedOffset += m.markerLen            // marker replaces needle
			origCursor = m.end
		} else {
			// Straddles: the needle starts in safe but ends in retained. We
			// cannot emit its bytes now; pull the safe boundary back to m.start
			// so the needle will be fully in the next round's retained buffer.
			actualSafeOrigLen = m.start
			break
		}
	}
	// Account for any remaining plain bytes from origCursor up to the
	// (possibly reduced) safe boundary.
	if origCursor < actualSafeOrigLen {
		redactedOffset += actualSafeOrigLen - origCursor
	}

	safeRedactedLen := min(redactedOffset, len(redacted))

	if safeRedactedLen > 0 {
		if _, err := sw.dst.Write(redacted[:safeRedactedLen]); err != nil {
			return err
		}
	}

	// Retain from actualSafeOrigLen (which may be shorter than safeOrigLen if
	// a straddling match forced the boundary back).
	retain := sw.pending[actualSafeOrigLen:]
	sw.pending = append(sw.pending[:0], retain...)
	return nil
}

// Flush drains any remaining bytes in the pending buffer through the redactor
// and writes them to dst. Calling Flush more than once is safe and idempotent.
func (sw *StreamingWriter) Flush() error {
	if len(sw.pending) == 0 {
		return nil
	}
	var redacted []byte
	if sw.ansiAware {
		redacted = sw.applyFormsANSI(sw.pending)
	} else {
		redacted = sw.applyForms(sw.pending)
	}
	sw.pending = sw.pending[:0]
	if len(redacted) > 0 {
		if _, err := sw.dst.Write(redacted); err != nil {
			return err
		}
	}
	return nil
}

// flushSafeANSI is the ANSI-aware analogue of flushSafe. It scans needles
// against the visible-byte projection of pending and replaces matched original
// spans with markers in the emitted bytes. The safe-to-emit boundary in
// original bytes is the smaller of (a) the original-position of the last
// lookbackSize visible byte and (b) len(pending) - inProgress (to keep any
// in-progress ANSI escape in the retain buffer). The boundary is pulled
// further back whenever a match straddles it.
func (sw *StreamingWriter) flushSafeANSI() error {
	visible, indexMap, inProgress := stripANSI(sw.pending)
	if len(visible) <= sw.lookbackSize {
		return nil
	}

	type match struct {
		origStart int
		origEnd   int
		marker    []byte
		itemName  string
	}
	var matches []match
	for _, f := range sw.forms {
		offset := 0
		src := visible
		for {
			idx := bytes.Index(src, f.needle)
			if idx < 0 {
				break
			}
			vStart := offset + idx
			vEnd := vStart + len(f.needle)
			origStart := indexMap[vStart]
			origEnd := indexMap[vEnd-1] + 1
			matches = append(matches, match{
				origStart: origStart,
				origEnd:   origEnd,
				marker:    f.marker,
				itemName:  f.itemName,
			})
			offset = vEnd
			src = visible[offset:]
		}
	}

	safeOrigLenByVisible := indexMap[len(visible)-sw.lookbackSize]
	safeOrigLen := len(sw.pending) - inProgress
	if safeOrigLenByVisible < safeOrigLen {
		safeOrigLen = safeOrigLenByVisible
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].origStart < matches[j].origStart
	})

	for _, m := range matches {
		if m.origStart >= safeOrigLen {
			continue
		}
		if m.origEnd > safeOrigLen {
			safeOrigLen = m.origStart
			break
		}
	}

	if safeOrigLen <= 0 {
		return nil
	}

	out := make([]byte, 0, safeOrigLen)
	cursor := 0
	for _, m := range matches {
		if m.origEnd > safeOrigLen {
			break
		}
		if m.origStart < cursor {
			continue
		}
		out = append(out, sw.pending[cursor:m.origStart]...)
		out = append(out, m.marker...)
		cursor = m.origEnd
		sw.redacted = true
		sw.matched[m.itemName] = true
	}
	out = append(out, sw.pending[cursor:safeOrigLen]...)

	if _, err := sw.dst.Write(out); err != nil {
		return err
	}

	retain := sw.pending[safeOrigLen:]
	sw.pending = append(sw.pending[:0], retain...)
	return nil
}

// applyFormsANSI is the one-shot (non-streaming) ANSI-aware redaction used by
// the final Flush. It scans visible bytes for needles, replaces matched
// original spans with markers, and otherwise preserves bytes including
// escape sequences.
func (sw *StreamingWriter) applyFormsANSI(chunk []byte) []byte {
	if len(chunk) == 0 {
		return nil
	}
	visible, indexMap, _ := stripANSI(chunk)
	type match struct {
		origStart int
		origEnd   int
		marker    []byte
		itemName  string
	}
	var matches []match
	for _, f := range sw.forms {
		offset := 0
		src := visible
		for {
			idx := bytes.Index(src, f.needle)
			if idx < 0 {
				break
			}
			vStart := offset + idx
			vEnd := vStart + len(f.needle)
			origStart := indexMap[vStart]
			origEnd := indexMap[vEnd-1] + 1
			matches = append(matches, match{
				origStart: origStart,
				origEnd:   origEnd,
				marker:    f.marker,
				itemName:  f.itemName,
			})
			offset = vEnd
			src = visible[offset:]
		}
	}
	if len(matches) == 0 {
		return append([]byte(nil), chunk...)
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].origStart < matches[j].origStart
	})
	out := make([]byte, 0, len(chunk))
	cursor := 0
	for _, m := range matches {
		if m.origStart < cursor {
			continue
		}
		out = append(out, chunk[cursor:m.origStart]...)
		out = append(out, m.marker...)
		cursor = m.origEnd
		sw.redacted = true
		sw.matched[m.itemName] = true
	}
	out = append(out, chunk[cursor:]...)
	return out
}

// Stats returns a snapshot of redaction metrics accumulated since construction.
func (sw *StreamingWriter) Stats() Stats {
	names := make([]string, 0, len(sw.matched))
	for n := range sw.matched {
		names = append(names, n)
	}
	sort.Strings(names)
	return Stats{
		Redacted:     sw.redacted,
		MatchedItems: names,
	}
}

// applyForms applies all needle forms to chunk and returns the redacted bytes,
// also updating sw.redacted and sw.matched.
func (sw *StreamingWriter) applyForms(chunk []byte) []byte {
	if len(chunk) == 0 {
		return nil
	}
	out := append([]byte(nil), chunk...)
	for _, f := range sw.forms {
		replaced, changed := replaceSpans(out, f.needle, f.marker)
		if changed {
			out = replaced
			sw.redacted = true
			sw.matched[f.itemName] = true
		}
	}
	return out
}
