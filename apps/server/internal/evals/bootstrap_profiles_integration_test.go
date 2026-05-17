//go:build integration

package evals

import (
	"encoding/json"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/profiles"
)

func TestBootstrapProfileSummaryEval(t *testing.T) {
	env := newEvalEnv(t)
	stdout, _, err := runHasp(t, env, "", "bootstrap", "profiles", "--json")
	if err != nil {
		t.Fatalf("bootstrap profiles failed: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("decode bootstrap profiles output: %v", err)
	}
	requiredSections, ok := payload["required_doc_sections"].([]any)
	if !ok || len(requiredSections) == 0 {
		t.Fatalf("expected required_doc_sections in bootstrap profiles output: %v", payload)
	}
	profilesValue, ok := payload["profiles"].([]any)
	if !ok || len(profilesValue) != 7 {
		t.Fatalf("expected seven shipped profiles, got %v", payload["profiles"])
	}
	firstProfile, ok := profilesValue[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected profile payload: %v", profilesValue[0])
	}
	if _, ok := firstProfile["release_gate"]; !ok {
		t.Fatalf("expected release gate in profile listing: %v", firstProfile)
	}
	if firstProfile["support_tier"] != profiles.SupportTierFirstClassShipped {
		t.Fatalf("expected first-class support tier, got %v", firstProfile["support_tier"])
	}
	genericPath, ok := payload["generic_path"].(map[string]any)
	if !ok {
		t.Fatalf("expected generic path in bootstrap profile summary: %v", payload)
	}
	if genericPath["first_class"] != false || genericPath["compatibility_label"] != profiles.CompatibilityLabelGeneric {
		t.Fatalf("unexpected generic path metadata: %v", genericPath)
	}
}
