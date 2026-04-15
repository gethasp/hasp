package redactor

import (
	"bytes"
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
