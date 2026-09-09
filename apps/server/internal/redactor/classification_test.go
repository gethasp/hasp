package redactor

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestClassificationControlsBatchAndStreamRedaction(t *testing.T) {
	value := []byte("1234567890123456")
	input := []byte("https://example.com/project/" + string(value) + " " + base64.StdEncoding.EncodeToString(value))
	for _, classification := range []store.ItemClassification{"", "unknown", store.ClassificationConfidential, store.ClassificationConfiguration} {
		item := store.Item{Name: "PROJECT_ID", Value: value, Classification: classification}
		for _, duplicate := range []bool{false, true} {
			items := []store.Item{item}
			if duplicate {
				items = append(items, store.Item{Name: "CONFIDENTIAL_COPY", Value: value})
			}
			wantRedacted := item.Confidential() || duplicate
			result := Apply(input, items)
			if result.Redacted != wantRedacted || bytes.Equal(result.Output, input) == wantRedacted {
				t.Fatalf("batch %s duplicate=%t: %+v", classification, duplicate, result)
			}
			var out bytes.Buffer
			stream := NewStreamingWriterANSIAware(&out, items)
			for _, b := range input {
				if _, err := stream.Write([]byte{b}); err != nil {
					t.Fatal(err)
				}
			}
			if err := stream.Flush(); err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(out.Bytes(), input) == wantRedacted || (wantRedacted && bytes.Contains(out.Bytes(), value)) {
				t.Fatalf("stream %s duplicate=%t: %q", classification, duplicate, out.Bytes())
			}
		}
	}
}
