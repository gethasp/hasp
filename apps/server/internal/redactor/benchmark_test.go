package redactor

import (
	"bytes"
	"fmt"
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
