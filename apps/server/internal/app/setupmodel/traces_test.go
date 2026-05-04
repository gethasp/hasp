package setupmodel

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestTracesAreDeterministic(t *testing.T) {
	first := CanonicalTraces()
	second := CanonicalTraces()

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("traces differ\nfirst=%+v\nsecond=%+v", first, second)
	}
}

func TestTracesContainOnlyAbstractPasswordClasses(t *testing.T) {
	blob, err := json.Marshal(CanonicalTraces())
	if err != nil {
		t.Fatalf("marshal traces: %v", err)
	}
	text := string(blob)

	for _, forbidden := range []string{
		"correct horse battery staple",
		"wrong password",
		"existing password",
		"secret",
		"password123",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("trace blob leaked forbidden plaintext")
		}
	}
}

func TestCanonicalTracesCoverRequiredOutcomes(t *testing.T) {
	traces := CanonicalTraces()
	names := map[string]bool{}
	for _, trace := range traces {
		names[trace.Name] = true
		if trace.Name == "" {
			t.Fatal("trace has empty name")
		}
		if strings.Contains(trace.Name, "correct horse") || strings.Contains(trace.Name, "wrong password") {
			t.Fatalf("trace name is not abstract: %q", trace.Name)
		}
	}

	for _, required := range []string{
		"new_strong_a_matches",
		"new_empty_then_strong_a_matches",
		"new_whitespace_then_strong_a_matches",
		"new_weak_retries_then_strong_a_matches",
		"new_skip_policy_weak_a_matches",
		"new_confirm_empty_then_strong_a_matches",
		"new_confirm_differs_then_strong_a_matches",
		"existing_empty_then_right",
		"existing_wrong_then_right",
		"existing_wrong_noninteractive_rejected",
		"env_empty_rejected",
		"stdin_empty_rejected",
		"prompt_reader_empty_eof_rejected",
		"interactive_empty_eof_then_interrupt",
		"empty_then_output_error",
		"empty_then_input_error",
	} {
		if !names[required] {
			t.Fatalf("missing canonical trace %q", required)
		}
	}
}
