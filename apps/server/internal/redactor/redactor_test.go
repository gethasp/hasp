package redactor

import (
	"encoding/base64"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestApplyRedactsManagedValuesAndBase64(t *testing.T) {
	item := store.Item{Name: "api_token", Value: []byte("secret-value")}
	text := []byte("token=secret-value b64=" + base64.StdEncoding.EncodeToString(item.Value))

	result := Apply(text, []store.Item{item})
	if !result.Redacted {
		t.Fatal("expected redaction")
	}
	if string(result.Output) == string(text) {
		t.Fatal("expected output to change")
	}
}

func TestApplySuppressesInvalidUTF8(t *testing.T) {
	item := store.Item{Name: "blob", Value: []byte{0xff, 0xfe}}
	result := Apply([]byte{0xff, 0xfe}, []store.Item{item})
	if !result.Suppressed {
		t.Fatal("expected invalid utf8 output to be suppressed")
	}
}

func TestApplyLeavesCleanTextUntouched(t *testing.T) {
	item := store.Item{Name: "api_token", Value: []byte("secret-value")}
	result := Apply([]byte("hello world"), []store.Item{item})
	if result.Redacted || result.Suppressed || string(result.Output) != "hello world" {
		t.Fatalf("unexpected clean result: %+v", result)
	}
}

func TestApplySkipsEmptyManagedValues(t *testing.T) {
	item := store.Item{Name: "empty", Value: []byte{}}
	result := Apply([]byte("hello world"), []store.Item{item})
	if result.Redacted || result.Suppressed {
		t.Fatalf("expected empty-value item to be ignored: %+v", result)
	}
}

func TestApplySuppressesOutputWhenReplacementBreaksUTF8(t *testing.T) {
	input := []byte("€")
	item := store.Item{Name: "byte", Value: []byte{0x82}}
	result := Apply(input, []store.Item{item})
	if !result.Suppressed || !result.Redacted {
		t.Fatalf("expected invalid utf8 output suppression, got %+v", result)
	}
}
