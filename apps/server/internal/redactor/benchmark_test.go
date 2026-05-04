package redactor

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func BenchmarkApplyManagedValues(b *testing.B) {
	items := []store.Item{
		{Name: "api_token", Value: []byte("abc123")},
		{Name: "db_url", Value: []byte("postgres://localhost")},
		{Name: "cert", Value: []byte("certificate-data")},
	}
	payload := bytes.Repeat([]byte("prefix abc123 middle postgres://localhost suffix certificate-data\n"), 50)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := Apply(payload, items)
		if !result.Redacted {
			b.Fatal("expected redaction")
		}
	}
}

func BenchmarkApplyManagedValuesLargeVault(b *testing.B) {
	for _, secretCount := range []int{100, 1000} {
		b.Run(fmt.Sprintf("secrets_%d", secretCount), func(b *testing.B) {
			items := benchmarkRedactorItems(secretCount)
			payload := benchmarkPayload10MB(items[secretCount-1].Value)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result := Apply(payload, items)
				if !result.Redacted {
					b.Fatal("expected redaction")
				}
			}
		})
	}
}

func TestApplyManagedValuesLargeVaultAllocationBudget(t *testing.T) {
	items := benchmarkRedactorItems(1000)
	payload := benchmarkPayload10MB(items[len(items)-1].Value)
	allocs := testing.AllocsPerRun(1, func() {
		result := Apply(payload, items)
		if !result.Redacted {
			t.Fatal("expected redaction")
		}
	})
	if allocs > 200_000 {
		t.Fatalf("large-vault redaction allocations %.0f exceed budget 200000", allocs)
	}
}

func TestApplySkipsEmptyAndShortValues(t *testing.T) {
	result := Apply([]byte("token=managed-secret"), []store.Item{
		{Name: "empty", Value: nil},
		{Name: "short", Value: []byte("tiny")},
		{Name: "secret", Value: []byte("managed-secret")},
	})
	if !result.Redacted {
		t.Fatal("expected long value to redact")
	}
	if bytes.Contains(result.Output, []byte("managed-secret")) {
		t.Fatalf("expected managed secret to be redacted, got %q", result.Output)
	}
	if len(result.MatchedItems) != 1 || result.MatchedItems[0] != "secret" {
		t.Fatalf("matched items = %v", result.MatchedItems)
	}
}

func TestApplyLargeVaultPrefilterSkipsAbsentForms(t *testing.T) {
	old := runtime.GOMAXPROCS(2)
	t.Cleanup(func() { runtime.GOMAXPROCS(old) })
	items := benchmarkRedactorItems(512)
	payload := benchmarkPayload10MB(items[len(items)-1].Value)
	result := Apply(payload, items)
	if !result.Redacted {
		t.Fatal("expected matched large-vault secret to redact")
	}
	if bytes.Contains(result.Output, items[len(items)-1].Value) {
		t.Fatal("expected matched secret to be removed")
	}
}

func TestDetectPresentFormsSmallInputReturnsNil(t *testing.T) {
	forms := [][]formDef{{{needle: []byte("managed-secret"), marker: []byte("[HASP:secret]")}}}
	if present := detectPresentForms([]byte("managed-secret"), forms, 1); present != nil {
		t.Fatalf("small input should skip prefilter, got %#v", present)
	}
}

func TestDetectPresentFormsSingleWorkerReturnsNil(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(old) })
	if present := detectPresentForms(benchmarkPayload10MB([]byte("managed-secret-0511-value")), benchmarkFormDefs(512), 512); present != nil {
		t.Fatalf("single-worker runtime should skip prefilter, got %#v", present)
	}
}

func TestDetectPresentFormsMarksOnlyPresentNeedles(t *testing.T) {
	old := runtime.GOMAXPROCS(513)
	t.Cleanup(func() { runtime.GOMAXPROCS(old) })
	forms := benchmarkFormDefs(512)
	input := benchmarkPayload10MB([]byte("managed-secret-0420-value"))
	present := detectPresentForms(input, forms, 512)
	if present == nil {
		t.Fatal("expected large input to use prefilter")
	}
	if !present[0][420] {
		t.Fatalf("expected present needle 420 to be marked: %#v", present[0][418:423])
	}
	if present[0][419] || present[0][421] {
		t.Fatalf("neighboring absent needles should stay false: %#v", present[0][418:423])
	}
}

func BenchmarkApplyLargeFileSecret(b *testing.B) {
	largeSecret := bytes.Repeat([]byte("CERTBLOCK0123456789"), 4096)
	items := []store.Item{{Name: "cert_file", Value: largeSecret}}
	payload := append([]byte("prefix "), largeSecret...)
	payload = append(payload, []byte(" suffix")...)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := Apply(payload, items)
		if !result.Redacted {
			b.Fatal("expected redaction")
		}
	}
}

func benchmarkRedactorItems(count int) []store.Item {
	items := make([]store.Item, 0, count)
	for i := 0; i < count; i++ {
		items = append(items, store.Item{
			Name:  fmt.Sprintf("secret_%04d", i),
			Value: []byte(fmt.Sprintf("managed-secret-%04d-value", i)),
		})
	}
	return items
}

func benchmarkPayload10MB(secret []byte) []byte {
	line := []byte("prefix " + string(secret) + " middle " + strings.Repeat("safe-data-", 32) + "\n")
	repeats := (10 << 20) / len(line)
	if repeats < 1 {
		repeats = 1
	}
	return bytes.Repeat(line, repeats)
}

func benchmarkFormDefs(count int) [][]formDef {
	forms := make([]formDef, 0, count)
	for i := 0; i < count; i++ {
		forms = append(forms, formDef{
			needle: []byte(fmt.Sprintf("managed-secret-%04d-value", i)),
			marker: []byte("[HASP:secret]"),
		})
	}
	return [][]formDef{forms}
}
