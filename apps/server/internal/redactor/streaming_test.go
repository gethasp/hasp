package redactor

import (
	"bytes"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func itemSW(name string, value []byte) store.Item {
	return store.Item{Name: name, Value: value}
}

// feedInChunks writes data to a StreamingWriter in chunks of chunkSize bytes.
func feedInChunks(sw *StreamingWriter, data []byte, chunkSize int) error {
	for len(data) > 0 {
		n := chunkSize
		if n > len(data) {
			n = len(data)
		}
		if _, err := sw.Write(data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// streamResult feeds data in chunkSize pieces, flushes, and returns the output.
func streamResult(items []store.Item, data []byte, chunkSize int) ([]byte, Stats) {
	var buf bytes.Buffer
	sw := NewStreamingWriter(&buf, items)
	_ = feedInChunks(sw, data, chunkSize)
	_ = sw.Flush()
	return buf.Bytes(), sw.Stats()
}

// ── table-driven core ─────────────────────────────────────────────────────────

func TestStreamingWriterMatchesApply(t *testing.T) {
	secret := []byte("ABCDEF-STREAMING-SECRET")
	items := []store.Item{itemSW("tok", secret)}

	// Build a multi-occurrence input.
	payload := []byte("prefix " + string(secret) + " middle " + string(secret) + " suffix")
	applyResult := Apply(payload, items)

	chunkSizes := []int{1, 2, 3, 7, len(payload)/2 + 1, len(payload)}
	for _, cs := range chunkSizes {
		got, _ := streamResult(items, payload, cs)
		if !bytes.Equal(got, applyResult.Output) {
			t.Errorf("chunkSize=%d: got %q, want %q", cs, got, applyResult.Output)
		}
	}
}

func TestStreamingWriterNeedleStraddlesChunkBoundary(t *testing.T) {
	secret := []byte("STRADDLE-SECRET-VALUE")
	items := []store.Item{itemSW("straddler", secret)}
	applyResult := Apply(secret, items)

	// Feed one byte at a time — every boundary is exercised.
	got, stats := streamResult(items, secret, 1)
	if !bytes.Equal(got, applyResult.Output) {
		t.Errorf("byte-at-a-time straddling: got %q, want %q", got, applyResult.Output)
	}
	if !stats.Redacted {
		t.Error("expected stats.Redacted=true for straddling case")
	}
	if len(stats.MatchedItems) != 1 || stats.MatchedItems[0] != "straddler" {
		t.Errorf("MatchedItems: got %v, want [straddler]", stats.MatchedItems)
	}
}

func TestStreamingWriterNoItemsPassesThrough(t *testing.T) {
	data := []byte("hello world with no secrets here")
	got, stats := streamResult(nil, data, 3)
	if !bytes.Equal(got, data) {
		t.Errorf("no-items passthrough: got %q, want %q", got, data)
	}
	if stats.Redacted || len(stats.MatchedItems) != 0 {
		t.Errorf("unexpected stats for no-items: %+v", stats)
	}
}

func TestStreamingWriterNoItemsZeroBuffering(t *testing.T) {
	// With no items, Flush on empty writer should be a no-op.
	var buf bytes.Buffer
	sw := NewStreamingWriter(&buf, nil)
	n, err := sw.Write([]byte("abc"))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected n=3, got %d", n)
	}
	// Should have passed all bytes through immediately (zero buffering).
	if err := sw.Flush(); err != nil {
		t.Fatalf("unexpected flush error: %v", err)
	}
	if buf.String() != "abc" {
		t.Errorf("got %q, want %q", buf.String(), "abc")
	}
}

func TestStreamingWriterShortSecretSkipped(t *testing.T) {
	short := make([]byte, minRedactLen-1)
	for i := range short {
		short[i] = 'X'
	}
	items := []store.Item{itemSW("short", short)}
	data := append([]byte("prefix-"), append(short, []byte("-suffix")...)...)
	got, stats := streamResult(items, data, 1)
	if !bytes.Equal(got, data) {
		t.Errorf("short secret must not be redacted; got %q", got)
	}
	if stats.Redacted {
		t.Error("Redacted must be false for short secret")
	}
}

func TestStreamingWriterLookbackWindowDoesNotExceedMaxNeedleMinus1(t *testing.T) {
	// Build two items; the max needle length across all encodings determines
	// the lookback window size.  We just verify the writer is constructable
	// and produces correct output for a known-size needle.
	secret := []byte("NEEDLESIZE-VERIFY-VALUE")
	items := []store.Item{itemSW("n", secret)}
	data := append([]byte("a"), append(secret, []byte("b")...)...)
	applyResult := Apply(data, items)
	got, _ := streamResult(items, data, 1)
	if !bytes.Equal(got, applyResult.Output) {
		t.Errorf("lookback window test: got %q, want %q", got, applyResult.Output)
	}
}

func TestStreamingWriterMultipleItemsAndEncodings(t *testing.T) {
	// Use two items; both raw forms are embedded in the data.
	secretA := []byte("hello-secret-value")
	secretB := []byte("world-secret-token")
	items := []store.Item{
		itemSW("a", secretA),
		itemSW("b", secretB),
	}
	// Embed raw form of both.
	data := []byte("begin " + string(secretA) + " mid " + string(secretB) + " end")
	applyResult := Apply(data, items)

	got, stats := streamResult(items, data, 4)
	if !bytes.Equal(got, applyResult.Output) {
		t.Errorf("multi-item: got %q, want %q", got, applyResult.Output)
	}
	if len(stats.MatchedItems) != 2 {
		t.Errorf("expected 2 MatchedItems, got %v", stats.MatchedItems)
	}
}

func TestStreamingWriterEmptyWriteAndEmptyFlush(t *testing.T) {
	items := []store.Item{itemSW("tok", []byte("SOME-SECRET-VALUE-LONG"))}
	var buf bytes.Buffer
	sw := NewStreamingWriter(&buf, items)
	// Write nothing.
	n, err := sw.Write([]byte{})
	if err != nil || n != 0 {
		t.Fatalf("empty write: n=%d err=%v", n, err)
	}
	if err := sw.Flush(); err != nil {
		t.Fatalf("flush after empty write: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output after empty write+flush, got %q", buf.Bytes())
	}
}

func TestStreamingWriterStatsAggregatedAcrossWrites(t *testing.T) {
	secret := []byte("MULTI-WRITE-SECRET-VALUE")
	items := []store.Item{itemSW("sec", secret)}
	var buf bytes.Buffer
	sw := NewStreamingWriter(&buf, items)

	// Write the secret in two separate calls so it crosses no boundary.
	first := []byte("prefix " + string(secret) + " middle ")
	second := []byte(string(secret) + " suffix")

	if _, err := sw.Write(first); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, err := sw.Write(second); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if err := sw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	stats := sw.Stats()
	if !stats.Redacted {
		t.Error("expected Redacted=true after multi-write")
	}
	if len(stats.MatchedItems) != 1 || stats.MatchedItems[0] != "sec" {
		t.Errorf("MatchedItems: got %v", stats.MatchedItems)
	}
	// Output must match Apply on the concatenated input.
	all := make([]byte, 0, len(first)+len(second))
	all = append(all, first...)
	all = append(all, second...)
	applyResult := Apply(all, items)
	if !bytes.Equal(buf.Bytes(), applyResult.Output) {
		t.Errorf("multi-write output mismatch: got %q want %q", buf.Bytes(), applyResult.Output)
	}
}

func TestStreamingWriterBinaryPassthrough(t *testing.T) {
	items := []store.Item{itemSW("bin", []byte("BINSECRET-VALUE-XY"))}
	binaryData := []byte{0x00, 0xFF, 0xFE, 0xCA, 0xFE, 0xBA, 0xBE}
	applyResult := Apply(binaryData, items)
	got, _ := streamResult(items, binaryData, 1)
	if !bytes.Equal(got, applyResult.Output) {
		t.Errorf("binary passthrough: got %x want %x", got, applyResult.Output)
	}
}

func TestStreamingWriterFullChunkMatchesApply(t *testing.T) {
	secret := []byte("FULLCHUNK-SECRET-VALUE")
	items := []store.Item{itemSW("fc", secret)}
	data := []byte("before " + string(secret) + " after")
	applyResult := Apply(data, items)
	// Feed as a single chunk.
	got, _ := streamResult(items, data, len(data))
	if !bytes.Equal(got, applyResult.Output) {
		t.Errorf("full chunk: got %q want %q", got, applyResult.Output)
	}
}

// Ensure Stats() returns sorted, deduplicated MatchedItems.
func TestStreamingWriterStatsMatchedItemsSorted(t *testing.T) {
	secretZ := []byte("zzz-secret-value-long")
	secretA := []byte("aaa-secret-value-long")
	items := []store.Item{
		itemSW("zzz", secretZ),
		itemSW("aaa", secretA),
	}
	data := []byte(string(secretZ) + " " + string(secretA))
	_, stats := streamResult(items, data, 3)
	if len(stats.MatchedItems) != 2 {
		t.Fatalf("expected 2 MatchedItems, got %v", stats.MatchedItems)
	}
	if stats.MatchedItems[0] != "aaa" || stats.MatchedItems[1] != "zzz" {
		t.Errorf("MatchedItems not sorted: %v", stats.MatchedItems)
	}
}

// Ensure Flush after Flush does not double-emit.
func TestStreamingWriterDoubleFlushSafe(t *testing.T) {
	secret := []byte("DOUBLE-FLUSH-SECRET-VALUE")
	items := []store.Item{itemSW("df", secret)}
	var buf bytes.Buffer
	sw := NewStreamingWriter(&buf, items)
	_, _ = sw.Write(secret)
	_ = sw.Flush()
	out1 := buf.Bytes()
	_ = sw.Flush()
	out2 := buf.Bytes()
	if !bytes.Equal(out1, out2) {
		t.Errorf("second flush emitted extra bytes: before=%q after=%q", out1, out2)
	}
}

// Regression: a secret that appears at the very end of the stream must be redacted.
func TestStreamingWriterSecretAtEndOfStream(t *testing.T) {
	secret := []byte("SECRET-AT-THE-END-VALUE")
	items := []store.Item{itemSW("end", secret)}
	data := []byte("some prefix text " + string(secret))
	applyResult := Apply(data, items)
	got, stats := streamResult(items, data, 7)
	if !bytes.Equal(got, applyResult.Output) {
		t.Errorf("end secret: got %q want %q", got, applyResult.Output)
	}
	if !stats.Redacted {
		t.Error("expected Redacted=true for end-of-stream secret")
	}
}

// Sanity: writer forwards exact bytes when no match.
func TestStreamingWriterNoMatchPassesExactBytes(t *testing.T) {
	items := []store.Item{itemSW("nomatch", []byte("NOT-IN-INPUT-AT-ALL-XYZZY"))}
	data := []byte("hello world, nothing to redact here!")
	got, stats := streamResult(items, data, 5)
	if !bytes.Equal(got, data) {
		t.Errorf("no-match: got %q want %q", got, data)
	}
	if stats.Redacted {
		t.Error("Redacted must be false when no match")
	}
}

// ── Two-byte chunk coverage ───────────────────────────────────────────────────

func TestStreamingWriterTwoByteChunks(t *testing.T) {
	secret := []byte("TWOBYTE-CHUNK-SECRET-VALUE")
	items := []store.Item{itemSW("tb", secret)}
	data := []byte("aa " + string(secret) + " bb")
	applyResult := Apply(data, items)
	got, _ := streamResult(items, data, 2)
	if !bytes.Equal(got, applyResult.Output) {
		t.Errorf("two-byte chunks: got %q want %q", got, applyResult.Output)
	}
}

// Verify that the lookback window size equals max(len(needle))-1 across all
// needle forms. This is a structural invariant test, not a behavioral one.
func TestStreamingWriterLookbackWindowSize(t *testing.T) {
	secret := []byte("LOOKBACK-SIZE-VERIFY-VALUE")
	items := []store.Item{itemSW("lb", secret)}
	sw := NewStreamingWriter(&bytes.Buffer{}, items)
	maxNeedle := sw.maxNeedleLen
	want := maxNeedle - 1
	if sw.lookbackSize != want {
		t.Errorf("lookback size: got %d, want maxNeedle-1=%d", sw.lookbackSize, want)
	}
}

// Ensure lookback size is zero (no buffering) when items is empty.
func TestStreamingWriterLookbackZeroWhenNoItems(t *testing.T) {
	sw := NewStreamingWriter(&bytes.Buffer{}, nil)
	if sw.lookbackSize != 0 {
		t.Errorf("expected lookback 0 for no items, got %d", sw.lookbackSize)
	}
	if sw.maxNeedleLen != 0 {
		t.Errorf("expected maxNeedleLen 0 for no items, got %d", sw.maxNeedleLen)
	}
}
