package redactor

// Encoding-form coverage for Needles / Apply (was hasp-ohub RED, now GREEN).
//
// Contract pinned and shipping:
//   - Needles produces base32 standard-encoded form of the secret.
//   - Needles produces HTML-entity-encoded form (hex entity per byte, e.g. &#x41;).
//   - Needles produces double-percent-encoded form (%2520 for a literal % byte).
//   - Needles produces unicode-escape form (\uXXXX per codepoint).
//   - Apply masks all four forms in addition to the existing ones.
//
// buildForms / Needles emit each form; these tests guard against regression.

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"net/url"
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

// ── Unpadded base64 + PathEscape coverage (hasp-g84c hardening) ────────────────
//
// JWTs, OAuth Bearer tokens, and k8s/iOS secret exporters emit base64 WITHOUT
// padding. URLs encode spaces as %20 (PathEscape) as often as '+' (QueryEscape).
// The padded-base64 and QueryEscape-only forms missed both; these guard the fix.

func needlesContain(needles [][]byte, want string) bool {
	for _, n := range needles {
		if string(n) == want {
			return true
		}
	}
	return false
}

func TestEncodingGapNeedlesIncludesRawBase64(t *testing.T) {
	// High bytes so the std alphabet ('+','/') and url alphabet ('-','_')
	// produce DIFFERENT output — proving both raw variants are emitted, not
	// just one.
	secret := []byte{0xFB, 0xFF, 0xFF, 0xFB, 0xFF, 0xFF}
	raw := base64.RawStdEncoding.EncodeToString(secret)
	rawURL := base64.RawURLEncoding.EncodeToString(secret)
	if raw == rawURL {
		t.Fatalf("test setup: chose a secret where std==url base64 (%q)", raw)
	}
	needles := Needles(secret)

	if !needlesContain(needles, raw) {
		t.Fatalf("Needles missing raw-std base64 form %q; got %v", raw, formatNeedles(needles))
	}
	if !needlesContain(needles, rawURL) {
		t.Fatalf("Needles missing raw-url base64 form %q; got %v", rawURL, formatNeedles(needles))
	}

	// Also pin the unpadded-vs-padded divergence for a typical token length.
	tok := []byte("AKIAIOSFODNN7EXAMPLE") // len%3==2 → padded ends in '='
	if !needlesContain(Needles(tok), base64.RawStdEncoding.EncodeToString(tok)) {
		t.Fatalf("Needles missing unpadded form of %q", tok)
	}
}

func TestEncodingGapApplyMasksRawBase64Form(t *testing.T) {
	secret := []byte("AKIAIOSFODNN7EXAMPLE")
	it := gapItem("raw-b64-secret", secret)
	raw := base64.RawStdEncoding.EncodeToString(secret)
	input := []byte("authorization: Bearer " + raw + " trailing")

	result := Apply(input, []store.Item{it})

	if !result.Redacted {
		t.Fatal("expected Redacted=true for unpadded base64 secret")
	}
	if bytes.Contains(result.Output, []byte(raw)) {
		t.Fatalf("output still contains raw base64 form %q; output: %s", raw, result.Output)
	}
}

func TestEncodingGapNeedlesIncludesPathEscape(t *testing.T) {
	secret := []byte("my secret pass") // spaces → %20 under PathEscape, '+' under QueryEscape
	pe := url.PathEscape(string(secret))
	needles := Needles(secret)

	for _, n := range needles {
		if string(n) == pe {
			return
		}
	}
	t.Fatalf("Needles missing PathEscape (%%20) form %q; got %v", pe, formatNeedles(needles))
}

func TestEncodingGapApplyMasksPathEscapeForm(t *testing.T) {
	secret := []byte("my secret pass")
	it := gapItem("pathescape-secret", secret)
	pe := url.PathEscape(string(secret))
	input := []byte("GET /q?v=" + pe + " HTTP/1.1")

	result := Apply(input, []store.Item{it})

	if !result.Redacted {
		t.Fatal("expected Redacted=true for %20-encoded secret")
	}
	if bytes.Contains(result.Output, []byte(pe)) {
		t.Fatalf("output still contains PathEscape form %q; output: %s", pe, result.Output)
	}
}

// TestEncodingGapApplyMasksPercentEncodedBase64Padding pins that base64 with
// percent-encoded padding (c2VjcmV0IQ%3D%3D in a URL) is redacted. This works
// because the unpadded base64 needle is a prefix substring of the %3D form, so
// the raw-base64 coverage (commit ad71efa2) already closes hasp-1kc4's %3D item.
func TestEncodingGapApplyMasksPercentEncodedBase64Padding(t *testing.T) {
	secret := []byte("super-secret-value")
	it := gapItem("pct-pad-secret", secret)
	std := base64.StdEncoding.EncodeToString(secret) // has '=' padding
	pct := strings.ReplaceAll(std, "=", "%3D")
	if pct == std {
		t.Skip("secret produced no padding; pick a value with len%3 != 0")
	}
	input := []byte("token=" + pct + "&next=1")

	result := Apply(input, []store.Item{it})

	if !result.Redacted {
		t.Fatal("expected Redacted=true for %3D-padded base64 secret")
	}
	// The unpadded base64 form must be gone from the output.
	if bytes.Contains(result.Output, []byte(base64.RawStdEncoding.EncodeToString(secret))) {
		t.Fatalf("output still exposes the base64 body of the secret: %s", result.Output)
	}
}
