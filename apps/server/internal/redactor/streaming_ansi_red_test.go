package redactor

import (
	"bytes"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// hasp-ab5d: the streaming redactor performs literal substring matching, so a
// child that emits a secret with embedded ANSI escape sequences (color, style,
// reset) bypasses redaction. PTY allocation (hasp-ymuy) is the trigger that
// makes children emit ANSI in the first place — without ANSI-aware redaction
// the PTY work would create a redaction-bypass vector.
//
// These tests assert the post-fix behaviour. Pre-fix they fail because
// bytes.Index never finds the needle when the secret straddles an ANSI
// sequence.

func TestStreamingWriter_ANSIBypass_SplitByCSI(t *testing.T) {
	// `AKIATEST123` split by an ANSI bold/reset around `TEST`. A literal
	// matcher sees the bytes `AKIA\x1b[1mTEST\x1b[0m123` which do not
	// contain `AKIATEST123` as a contiguous substring.
	secret := []byte("AKIATEST123")
	input := []byte("payload AKIA\x1b[1mTEST\x1b[0m123 trailing")

	var buf bytes.Buffer
	sw := NewStreamingWriterANSIAware(&buf, []store.Item{{Name: "key", Value: secret}})
	if _, err := sw.Write(input); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	out := buf.Bytes()
	if bytes.Contains(out, secret) {
		t.Fatalf("ANSI-aware streaming writer leaked the secret literal: %q", out)
	}
	if !sw.Stats().Redacted {
		t.Fatalf("expected Redacted=true after matching across ANSI boundary; out=%q", out)
	}
	if got := len(sw.Stats().MatchedItems); got != 1 || sw.Stats().MatchedItems[0] != "key" {
		t.Fatalf("expected MatchedItems=[key], got %v", sw.Stats().MatchedItems)
	}
}

func TestStreamingWriter_ANSIBypass_LeadingFormat(t *testing.T) {
	// All ANSI is outside the secret span. Must still redact.
	secret := []byte("hunter2pass")
	input := []byte("\x1b[31mhunter2pass\x1b[0m\n")

	var buf bytes.Buffer
	sw := NewStreamingWriterANSIAware(&buf, []store.Item{{Name: "p", Value: secret}})
	if _, err := sw.Write(input); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if bytes.Contains(buf.Bytes(), secret) {
		t.Fatalf("leaked the secret with leading ANSI: %q", buf.Bytes())
	}
}

func TestStreamingWriter_ANSIBypass_StraddlingWriteBoundary(t *testing.T) {
	// The ANSI escape itself is split across two Write() calls. The writer
	// must not flush a partial `\x1b[` until the sequence terminates,
	// otherwise the next round's lookback can't recognise the secret.
	secret := []byte("AKIATEST123")
	var buf bytes.Buffer
	sw := NewStreamingWriterANSIAware(&buf, []store.Item{{Name: "k", Value: secret}})
	if _, err := sw.Write([]byte("AKIA\x1b[")); err != nil {
		t.Fatalf("write1: %v", err)
	}
	if _, err := sw.Write([]byte("1mTEST\x1b[0m123 tail")); err != nil {
		t.Fatalf("write2: %v", err)
	}
	if err := sw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if bytes.Contains(buf.Bytes(), secret) {
		t.Fatalf("leaked secret across write boundary: %q", buf.Bytes())
	}
}

func TestStreamingWriter_ANSI_Default_DoesNotChangeBehaviour(t *testing.T) {
	// Plain (non-ANSI) input must behave identically with or without the
	// ANSI-aware option so existing callers that don't opt in see no
	// performance or correctness change.
	secret := []byte("AKIATEST123")
	input := []byte("payload AKIATEST123 tail")

	var bufA, bufB bytes.Buffer
	a := NewStreamingWriter(&bufA, []store.Item{{Name: "k", Value: secret}})
	b := NewStreamingWriterANSIAware(&bufB, []store.Item{{Name: "k", Value: secret}})
	for _, w := range []*StreamingWriter{a, b} {
		if _, err := w.Write(input); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := w.Flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
	}
	if !bytes.Equal(bufA.Bytes(), bufB.Bytes()) {
		t.Fatalf("ANSI-aware option changed plain-text output:\n  default=%q\n  ansi=%q", bufA.Bytes(), bufB.Bytes())
	}
}

func TestStreamingWriter_ANSI_PreservesNonSecretEscapes(t *testing.T) {
	// ANSI sequences not bracketing a secret must pass through untouched so
	// the user still sees colored output for whatever the child wrote.
	secret := []byte("hunter2pass")
	input := []byte("\x1b[32mok\x1b[0m: hunter2pass and \x1b[31mfail\x1b[0m\n")

	var buf bytes.Buffer
	sw := NewStreamingWriterANSIAware(&buf, []store.Item{{Name: "p", Value: secret}})
	if _, err := sw.Write(input); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	out := buf.Bytes()
	if bytes.Contains(out, secret) {
		t.Fatalf("leaked secret: %q", out)
	}
	for _, esc := range [][]byte{[]byte("\x1b[32m"), []byte("\x1b[31m"), []byte("\x1b[0m")} {
		if !bytes.Contains(out, esc) {
			t.Fatalf("ANSI-aware writer dropped non-secret escape %q from %q", esc, out)
		}
	}
}
