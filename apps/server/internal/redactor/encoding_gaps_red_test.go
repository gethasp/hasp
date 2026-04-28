package redactor

// RED tests for hasp-ohub — encoding gaps in Needles / Apply.
//
// Contract pinned (not yet implemented):
//   - Needles produces base32 standard-encoded form of the secret.
//   - Needles produces HTML-entity-encoded form (hex entity per byte, e.g. &#x41;).
//   - Needles produces double-percent-encoded form (%2520 for a literal % byte).
//   - Needles produces unicode-escape form (\uXXXX per codepoint).
//   - Apply masks all four new forms in addition to the existing forms.
//
// These tests are intentionally RED: production code does not yet emit these
// forms. GREEN phase must add them to buildForms / Needles.

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// sampleSecret is long enough to pass minRedactLen (6) across all sub-tests.
var sampleSecret = []byte("Secret7!")

// ── helper ───────────────────────────────────────────────────────────────────

func gapItem(name string, value []byte) store.Item {
	return store.Item{Name: name, Value: value}
}

// htmlEntityEncode encodes every byte as a hex HTML character reference.
// Example: 'A' → "&#x41;"
func htmlEntityEncode(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		fmt.Fprintf(&sb, "&#x%02X;", c)
	}
	return sb.String()
}

// doublePercentEncode percent-encodes every byte of s and then percent-encodes
// the resulting '%' signs so '%41' becomes '%2541'.
func doublePercentEncode(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		fmt.Fprintf(&sb, "%%25%02X", c)
	}
	return sb.String()
}

// unicodeEscape encodes every rune in s as a \uXXXX sequence (BMP only for
// simplicity; supplementary planes would need \UXXXXXXXX).
func unicodeEscape(b []byte) string {
	var sb strings.Builder
	s := string(b)
	for _, r := range s {
		if r > utf8.MaxRune {
			continue
		}
		fmt.Fprintf(&sb, "\\u%04X", r)
	}
	return sb.String()
}

// ── Needles tests ─────────────────────────────────────────────────────────────

func TestEncodingGapNeedlesIncludesBase32(t *testing.T) {
	secret := sampleSecret
	b32 := base32.StdEncoding.EncodeToString(secret)
	needles := Needles(secret)

	for _, n := range needles {
		if string(n) == b32 {
			return // found — test would pass; in RED phase this never happens
		}
	}
	t.Fatalf("Needles did not include base32 form %q; got %d needles: %v",
		b32, len(needles), formatNeedles(needles))
}

func TestEncodingGapNeedlesIncludesHTMLEntity(t *testing.T) {
	secret := sampleSecret
	entity := htmlEntityEncode(secret)
	needles := Needles(secret)

	for _, n := range needles {
		if string(n) == entity {
			return
		}
	}
	t.Fatalf("Needles did not include HTML-entity form %q; got %d needles: %v",
		entity, len(needles), formatNeedles(needles))
}

func TestEncodingGapNeedlesIncludesDoublePercentEncoded(t *testing.T) {
	// Use a secret that contains a percent sign so double-encoding is visible.
	secret := []byte("pass%word!")
	dpe := doublePercentEncode(secret)
	needles := Needles(secret)

	for _, n := range needles {
		if string(n) == dpe {
			return
		}
	}
	t.Fatalf("Needles did not include double-percent-encoded form %q; got %d needles: %v",
		dpe, len(needles), formatNeedles(needles))
}

func TestEncodingGapNeedlesIncludesUnicodeEscape(t *testing.T) {
	secret := sampleSecret
	ue := unicodeEscape(secret)
	needles := Needles(secret)

	for _, n := range needles {
		if string(n) == ue {
			return
		}
	}
	t.Fatalf("Needles did not include unicode-escape form %q; got %d needles: %v",
		ue, len(needles), formatNeedles(needles))
}

// ── Apply integration tests ───────────────────────────────────────────────────

func TestEncodingGapApplyMasksBase32Form(t *testing.T) {
	secret := sampleSecret
	it := gapItem("base32-secret", secret)
	b32 := base32.StdEncoding.EncodeToString(secret)
	input := []byte("encoded=" + b32 + " rest")

	result := Apply(input, []store.Item{it})

	if !result.Redacted {
		t.Fatal("expected Redacted=true for base32-encoded secret")
	}
	if bytes.Contains(result.Output, []byte(b32)) {
		t.Fatalf("output still contains base32 form %q; output: %s", b32, result.Output)
	}
}

func TestEncodingGapApplyMasksHTMLEntityForm(t *testing.T) {
	secret := sampleSecret
	it := gapItem("html-entity-secret", secret)
	entity := htmlEntityEncode(secret)
	input := []byte("value=" + entity + " end")

	result := Apply(input, []store.Item{it})

	if !result.Redacted {
		t.Fatal("expected Redacted=true for HTML-entity-encoded secret")
	}
	if bytes.Contains(result.Output, []byte(entity)) {
		t.Fatalf("output still contains HTML-entity form %q; output: %s", entity, result.Output)
	}
}

func TestEncodingGapApplyMasksDoublePercentForm(t *testing.T) {
	secret := []byte("pass%word!")
	it := gapItem("dpe-secret", secret)
	dpe := doublePercentEncode(secret)
	input := []byte("q=" + dpe + "&other=x")

	result := Apply(input, []store.Item{it})

	if !result.Redacted {
		t.Fatal("expected Redacted=true for double-percent-encoded secret")
	}
	if bytes.Contains(result.Output, []byte(dpe)) {
		t.Fatalf("output still contains double-percent form %q; output: %s", dpe, result.Output)
	}
}

func TestEncodingGapApplyMasksUnicodeEscapeForm(t *testing.T) {
	secret := sampleSecret
	it := gapItem("unicode-escape-secret", secret)
	ue := unicodeEscape(secret)
	input := []byte(`{"key":"` + ue + `"}`)

	result := Apply(input, []store.Item{it})

	if !result.Redacted {
		t.Fatal("expected Redacted=true for unicode-escape-encoded secret")
	}
	if bytes.Contains(result.Output, []byte(ue)) {
		t.Fatalf("output still contains unicode-escape form %q; output: %s", ue, result.Output)
	}
}

// ── internal helper ───────────────────────────────────────────────────────────

func formatNeedles(needles [][]byte) []string {
	out := make([]string, len(needles))
	for i, n := range needles {
		out[i] = string(n)
	}
	return out
}
