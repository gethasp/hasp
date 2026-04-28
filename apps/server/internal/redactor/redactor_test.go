package redactor

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// minRedactLen is a package-level constant GREEN must define.
// Tests reference it directly so the threshold is never hard-coded twice.

// ── helpers ─────────────────────────────────────────────────────────────────

func item(name string, value []byte) store.Item {
	return store.Item{Name: name, Value: value}
}

// ── existing contract (still valid) ─────────────────────────────────────────

func TestApplyLeavesCleanTextUntouched(t *testing.T) {
	it := item("api_token", []byte("secret-value"))
	result := Apply([]byte("hello world"), []store.Item{it})
	if result.Redacted || result.Suppressed || string(result.Output) != "hello world" {
		t.Fatalf("unexpected clean result: %+v", result)
	}
}

func TestApplySkipsEmptyManagedValues(t *testing.T) {
	it := item("empty", []byte{})
	result := Apply([]byte("hello world"), []store.Item{it})
	if result.Redacted || result.Suppressed {
		t.Fatalf("expected empty-value item to be ignored: %+v", result)
	}
	if len(result.MatchedItems) != 0 {
		t.Fatalf("expected MatchedItems empty, got %v", result.MatchedItems)
	}
}

// ── new required tests ───────────────────────────────────────────────────────

// 1. Raw span redaction
func TestApplyRedactsRawValueSpan(t *testing.T) {
	secret := []byte("ABCDEF-SECRET-XYZ")
	it := item("my-token", secret)
	input := []byte("token=ABCDEF-SECRET-XYZ rest")

	result := Apply(input, []store.Item{it})

	if !result.Redacted {
		t.Fatal("expected Redacted=true")
	}
	if bytes.Contains(result.Output, secret) {
		t.Fatal("output still contains raw secret")
	}
	if !bytes.Contains(result.Output, []byte("[REDACTED]")) {
		t.Fatal("expected [REDACTED] marker in output")
	}
	if len(result.MatchedItems) != 1 || result.MatchedItems[0] != "my-token" {
		t.Fatalf("expected MatchedItems=[my-token], got %v", result.MatchedItems)
	}
}

// 2. Base64 std-encoded value redaction
func TestApplyRedactsBase64StdEncodedValue(t *testing.T) {
	secret := []byte("super-secret-bytes")
	it := item("b64-item", secret)
	encoded := base64.StdEncoding.EncodeToString(secret)
	input := []byte("value=" + encoded)

	result := Apply(input, []store.Item{it})

	if !result.Redacted {
		t.Fatal("expected Redacted=true")
	}
	if bytes.Contains(result.Output, []byte(encoded)) {
		t.Fatal("output still contains base64 std encoded secret")
	}
	if len(result.MatchedItems) != 1 || result.MatchedItems[0] != "b64-item" {
		t.Fatalf("expected MatchedItems=[b64-item], got %v", result.MatchedItems)
	}
}

// 3. Base64 URL-encoded value redaction
func TestApplyRedactsBase64URLEncodedValue(t *testing.T) {
	secret := []byte("url-safe-secret!!")
	it := item("b64url-item", secret)
	encoded := base64.URLEncoding.EncodeToString(secret)
	input := []byte("value=" + encoded)

	result := Apply(input, []store.Item{it})

	if !result.Redacted {
		t.Fatal("expected Redacted=true")
	}
	if bytes.Contains(result.Output, []byte(encoded)) {
		t.Fatal("output still contains base64 URL encoded secret")
	}
	if len(result.MatchedItems) != 1 || result.MatchedItems[0] != "b64url-item" {
		t.Fatalf("expected MatchedItems=[b64url-item], got %v", result.MatchedItems)
	}
}

// 4. Hex lowercase redaction
func TestApplyRedactsHexLowercase(t *testing.T) {
	secret := []byte("hexsecretvalue!!")
	it := item("hex-item", secret)
	encoded := hex.EncodeToString(secret) // lowercase by default
	input := []byte("digest=" + encoded)

	result := Apply(input, []store.Item{it})

	if !result.Redacted {
		t.Fatal("expected Redacted=true")
	}
	if bytes.Contains(result.Output, []byte(encoded)) {
		t.Fatal("output still contains hex-lowercase encoded secret")
	}
	if len(result.MatchedItems) != 1 || result.MatchedItems[0] != "hex-item" {
		t.Fatalf("expected MatchedItems=[hex-item], got %v", result.MatchedItems)
	}
}

// 5. Hex uppercase redaction
func TestApplyRedactsHexUppercase(t *testing.T) {
	secret := []byte("hexsecretvalue!!")
	it := item("hex-upper-item", secret)
	encoded := strings.ToUpper(hex.EncodeToString(secret))
	input := []byte("digest=" + encoded)

	result := Apply(input, []store.Item{it})

	if !result.Redacted {
		t.Fatal("expected Redacted=true")
	}
	if bytes.Contains(result.Output, []byte(encoded)) {
		t.Fatal("output still contains hex-uppercase encoded secret")
	}
	if len(result.MatchedItems) != 1 || result.MatchedItems[0] != "hex-upper-item" {
		t.Fatalf("expected MatchedItems=[hex-upper-item], got %v", result.MatchedItems)
	}
}

// 6. URL-encoded (percent-encoded) value redaction
func TestApplyRedactsURLEncodedValue(t *testing.T) {
	secret := []byte("p@ssw0rd&key=val")
	it := item("url-item", secret)
	encoded := url.QueryEscape(string(secret))
	input := []byte("creds=" + encoded)

	result := Apply(input, []store.Item{it})

	if !result.Redacted {
		t.Fatal("expected Redacted=true")
	}
	if bytes.Contains(result.Output, []byte(encoded)) {
		t.Fatal("output still contains URL encoded secret")
	}
	if len(result.MatchedItems) != 1 || result.MatchedItems[0] != "url-item" {
		t.Fatalf("expected MatchedItems=[url-item], got %v", result.MatchedItems)
	}
}

// 7. JSON-string-escaped value redaction
func TestApplyRedactsJSONStringEscapedValue(t *testing.T) {
	secret := []byte("line1\nline2\t\"quoted\"\\back")
	it := item("json-item", secret)
	b, _ := json.Marshal(string(secret))
	// b is e.g. `"line1\nline2\t\"quoted\"\\back"` — strip surrounding quotes
	encoded := string(b[1 : len(b)-1])
	input := []byte(`{"key":"` + encoded + `"}`)

	result := Apply(input, []store.Item{it})

	if !result.Redacted {
		t.Fatal("expected Redacted=true")
	}
	if bytes.Contains(result.Output, []byte(encoded)) {
		t.Fatal("output still contains JSON-escaped secret")
	}
	if len(result.MatchedItems) != 1 || result.MatchedItems[0] != "json-item" {
		t.Fatalf("expected MatchedItems=[json-item], got %v", result.MatchedItems)
	}
}

// 8. Binary input: only matched span is replaced; surrounding bytes pass through
func TestApplyPreservesBinaryInputRedactingOnlyMatchedSpan(t *testing.T) {
	secret := []byte("MATCHME-SECRET-VALUE")
	it := item("bin-item", secret)

	prefix := []byte{0x00, 0xFF, 0xFE}
	suffix := []byte{0xCA, 0xFE}
	input := append(append(append([]byte(nil), prefix...), secret...), suffix...)

	result := Apply(input, []store.Item{it})

	if result.Suppressed {
		t.Fatal("Suppressed must be false for binary input — new contract")
	}
	if !result.Redacted {
		t.Fatal("expected Redacted=true")
	}
	if bytes.Contains(result.Output, secret) {
		t.Fatal("output still contains raw secret bytes")
	}
	// Surrounding binary bytes must be preserved verbatim.
	if !bytes.HasPrefix(result.Output, prefix) {
		t.Fatalf("binary prefix 0x00 0xFF 0xFE not preserved; output: %x", result.Output)
	}
	if !bytes.HasSuffix(result.Output, suffix) {
		t.Fatalf("binary suffix 0xCA 0xFE not preserved; output: %x", result.Output)
	}
}

// 9. Binary input with no matching secret — output is byte-identical to input
func TestApplyPreservesBinaryInputWithoutMatches(t *testing.T) {
	input := []byte{0x00, 0xFF, 0xFE, 0xCA, 0xFE}
	it := item("nomatch", []byte("ABCDEF-SECRET-XYZ-NOT-IN-INPUT"))
	result := Apply(input, []store.Item{it})

	if result.Redacted {
		t.Fatal("expected Redacted=false")
	}
	if result.Suppressed {
		t.Fatal("expected Suppressed=false")
	}
	if !bytes.Equal(result.Output, input) {
		t.Fatalf("expected output == input byte-for-byte; got %x", result.Output)
	}
}

// 10. Short secrets below minRedactLen are silently skipped
func TestApplySkipsShortSecretsBelowMinLen(t *testing.T) {
	// Build a value that is guaranteed shorter than minRedactLen.
	// We use a loop to construct it so the test self-adapts to any threshold.
	shortValue := make([]byte, minRedactLen-1)
	for i := range shortValue {
		shortValue[i] = 'X'
	}
	it := item("short-secret", shortValue)
	input := append([]byte("prefix-"), shortValue...)
	input = append(input, []byte("-suffix")...)

	result := Apply(input, []store.Item{it})

	if result.Redacted {
		t.Fatal("expected Redacted=false: secret shorter than minRedactLen must not be redacted")
	}
	if len(result.MatchedItems) != 0 {
		t.Fatalf("expected MatchedItems empty, got %v", result.MatchedItems)
	}
	if !bytes.Equal(result.Output, input) {
		t.Fatal("output should be unchanged when short secret is skipped")
	}
}

// 11. MatchedItems is sorted and deduplicated across multiple items and multiple occurrences
func TestApplyMatchedItemsIsSortedAndDeduplicated(t *testing.T) {
	valAlpha := []byte("alpha-secret-value-long")
	valBeta := []byte("beta-secret-value-long!")
	itAlpha := item("alpha", valAlpha)
	itBeta := item("beta", valBeta)

	// beta first in input, alpha second; alpha appears twice
	input := append(append(append(append([]byte(nil), valBeta...), []byte(" mid ")...), valAlpha...), append([]byte(" end "), valAlpha...)...)

	result := Apply(input, []store.Item{itAlpha, itBeta})

	if !result.Redacted {
		t.Fatal("expected Redacted=true")
	}
	want := []string{"alpha", "beta"}
	if len(result.MatchedItems) != len(want) {
		t.Fatalf("expected MatchedItems=%v, got %v", want, result.MatchedItems)
	}
	if !sort.StringsAreSorted(result.MatchedItems) {
		t.Fatalf("MatchedItems must be sorted; got %v", result.MatchedItems)
	}
	for i, w := range want {
		if result.MatchedItems[i] != w {
			t.Fatalf("MatchedItems[%d]: want %q, got %q", i, w, result.MatchedItems[i])
		}
	}
}

// ── anti-requirements (inverted from old suppression behavior) ───────────────

// 14. Invalid UTF-8 input with NO matching secret must pass through unchanged (not suppressed)
func TestApplyDoesNotGloballySuppressOnInvalidUTF8Input(t *testing.T) {
	input := []byte{0xFF, 0xFE, 0x80, 0x81} // invalid UTF-8
	it := item("nomatch", []byte("ABCDEF-SECRET-NOT-HERE"))
	result := Apply(input, []store.Item{it})

	if result.Suppressed {
		t.Fatal("Suppressed must be false — invalid UTF-8 input must not be globally suppressed")
	}
	if result.Redacted {
		t.Fatal("Redacted must be false — no secret matched")
	}
	if !bytes.Equal(result.Output, input) {
		t.Fatalf("output must equal input byte-for-byte; got %x", result.Output)
	}
}

// 15. Replacement that creates invalid UTF-8 must NOT globally suppress; Suppressed=false, Redacted=true
func TestApplyDoesNotGloballySuppressWhenReplacementCreatesInvalidUTF8(t *testing.T) {
	// "€" is 0xE2 0x82 0xAC — use the middle byte 0x82 as the secret value.
	// Redacting 0x82 splits the multi-byte rune, leaving the output non-UTF-8.
	// The old behavior suppressed this; the new contract must NOT.
	// We need a secret of length >= minRedactLen that appears inside the input.
	// Since the full input is only 3 bytes we must match all 3 bytes to guarantee
	// the value is at least minRedactLen long — but 3 < 6.
	// Strategy: embed the multi-byte rune inside a longer binary input so the
	// surrounding context doesn't form valid UTF-8 after redaction.
	secret := []byte("€SECRET-LONG-ENOUGH") // starts with the 3-byte rune
	padding := []byte{0x80, 0x81}            // invalid UTF-8 continuation bytes
	input2 := append(append([]byte(nil), secret...), padding...)
	it := item("utf8breaker", secret)

	result := Apply(input2, []store.Item{it})

	if result.Suppressed {
		t.Fatal("Suppressed must be false — span redaction must not globally suppress output")
	}
	if !result.Redacted {
		t.Fatal("Redacted must be true — the secret was matched and redacted")
	}
}
