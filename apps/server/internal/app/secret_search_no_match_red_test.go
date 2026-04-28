package app

// hasp-dhd4: secret search no-match output claims vault is empty.
// `hasp secret search xyz_no_match` on a populated vault emits the same
// "No secrets stored in the vault." message as an empty vault.  These
// RED tests define the desired behaviour:
//  - non-empty vault, no filter hits → "no matches for <query>" (human)
//  - empty vault → "No secrets stored" still applies (human)
//  - JSON: no-match case carries total>0 + match_count:0; empty carries total:0

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/ui"
)

// TestSecretSearchNoMatch_HumanDistinguishesNoMatchFromEmpty verifies that
// when the vault has secrets but none match the query the human output says
// "no matches for" and references the query string — NOT "No secrets stored
// in the vault."
func TestSecretSearchNoMatch_HumanDistinguishesNoMatchFromEmpty(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	for _, name := range []string{"OPENAI_API_KEY", "STRIPE_SECRET", "GITHUB_TOKEN"} {
		if err := Run(context.Background(), []string{"secret", "add", "--from-stdin", "--vault-only", name},
			bytes.NewBufferString("redacted-value"), io.Discard, io.Discard); err != nil {
			t.Fatalf("secret add %s: %v", name, err)
		}
	}

	const query = "xyz_no_match_hasp_dhd4"
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "search", query}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("secret search returned unexpected error: %v", err)
	}

	got := out.String()

	// Must NOT claim the vault is empty — that is a lie when secrets exist.
	if strings.Contains(strings.ToLower(got), "no secrets stored") {
		t.Errorf("human output must not say 'no secrets stored' for a no-match on a populated vault; got:\n%s", got)
	}

	// Must convey that the vault was searched and nothing matched.
	if !strings.Contains(strings.ToLower(got), "no matches") {
		t.Errorf("human output must contain 'no matches' for a filter miss; got:\n%s", got)
	}

	// Must reference the query so operators know what they searched for.
	if !strings.Contains(got, query) {
		t.Errorf("human output must reference the search query %q; got:\n%s", query, got)
	}
}

// TestSecretSearchNoMatch_EmptyVaultStillSaysNoSecretsStored verifies that an
// empty vault (no filter, just nothing there) still emits the original
// "No secrets stored" message.  The two cases must be distinguishable.
func TestSecretSearchNoMatch_EmptyVaultStillSaysNoSecretsStored(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Vault is empty — searching for anything should say vault is empty, not
	// "no matches for" which would imply there were other items.
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "search", "any_query"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("secret search on empty vault: %v", err)
	}

	got := out.String()

	// The original empty-vault message should appear for a truly empty vault.
	if !strings.Contains(strings.ToLower(got), "no secrets stored") {
		t.Errorf("empty-vault search must say 'no secrets stored'; got:\n%s", got)
	}

	// Must NOT say "no matches for" when the vault is actually empty.
	if strings.Contains(strings.ToLower(got), "no matches") {
		t.Errorf("empty-vault search must not say 'no matches' (misleading); got:\n%s", got)
	}
}

// TestSecretSearchNoMatch_JSONDistinguishesFilterMissFromEmpty verifies that
// the JSON branch returns a structured payload that clearly distinguishes a
// filter miss (vault has items, none match) from an empty vault.
//
// Expected shape for filter miss:
//
//	{ "secrets": [], "match_count": 0, "total": N }  where N > 0
//
// Expected shape for empty vault:
//
//	{ "secrets": [], "match_count": 0, "total": 0 }
func TestSecretSearchNoMatch_JSONDistinguishesFilterMissFromEmpty(t *testing.T) {
	t.Run("populated vault no match", func(t *testing.T) {
		lockAppSeams(t)
		t.Setenv("HASP_HOME", t.TempDir())
		t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

		if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
			t.Fatalf("init: %v", err)
		}
		for _, name := range []string{"AWS_ACCESS_KEY", "DB_PASSWORD"} {
			if err := Run(context.Background(), []string{"secret", "add", "--from-stdin", "--vault-only", name},
				bytes.NewBufferString("s3cr3t"), io.Discard, io.Discard); err != nil {
				t.Fatalf("secret add %s: %v", name, err)
			}
		}

		var out bytes.Buffer
		if err := Run(context.Background(), []string{"secret", "search", "--json", "xyz_no_match_hasp_dhd4"},
			bytes.NewBuffer(nil), &out, io.Discard); err != nil {
			t.Fatalf("secret search --json: %v", err)
		}

		var payload map[string]any
		if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
			t.Fatalf("decode JSON: %v (raw: %s)", err, out.String())
		}

		// secrets array must be present and empty.
		secrets, ok := payload["secrets"].([]any)
		if !ok {
			t.Fatalf("expected 'secrets' array in payload; got keys: %v", searchPayloadKeys(payload))
		}
		if len(secrets) != 0 {
			t.Errorf("expected 0 matched secrets, got %d", len(secrets))
		}

		// total must reflect actual vault size (> 0).
		total, hasTotal := numericField(payload, "total")
		if !hasTotal {
			t.Errorf("JSON payload missing 'total' field distinguishing filter miss from empty vault; keys: %v", searchPayloadKeys(payload))
		} else if total <= 0 {
			t.Errorf("expected total > 0 for populated vault, got %v", total)
		}

		// match_count must be 0.
		matchCount, hasMatch := numericField(payload, "match_count")
		if !hasMatch {
			t.Errorf("JSON payload missing 'match_count' field; keys: %v", searchPayloadKeys(payload))
		} else if matchCount != 0 {
			t.Errorf("expected match_count == 0, got %v", matchCount)
		}
	})

	t.Run("empty vault", func(t *testing.T) {
		lockAppSeams(t)
		t.Setenv("HASP_HOME", t.TempDir())
		t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

		if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
			t.Fatalf("init: %v", err)
		}

		var out bytes.Buffer
		if err := Run(context.Background(), []string{"secret", "search", "--json", "any_query"},
			bytes.NewBuffer(nil), &out, io.Discard); err != nil {
			t.Fatalf("secret search --json on empty vault: %v", err)
		}

		var payload map[string]any
		if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
			t.Fatalf("decode JSON: %v (raw: %s)", err, out.String())
		}

		total, hasTotal := numericField(payload, "total")
		if !hasTotal {
			t.Errorf("JSON payload missing 'total' field; keys: %v", searchPayloadKeys(payload))
		} else if total != 0 {
			t.Errorf("expected total == 0 for empty vault, got %v", total)
		}
	})
}

// TestSecretSearchNoMatch_RenderSecretListWithColorNotCalledForFilterMiss is a
// boundary test verifying that the search rendering path does not emit
// "No secrets stored in the vault." when the vault has items but none match.
// It calls renderSecretSearchJSONOrHuman directly to confirm the filter-miss
// branch emits the correct "no matches for" message instead.
func TestSecretSearchNoMatch_RenderSecretListWithColorNotCalledForFilterMiss(t *testing.T) {
	// Simulate a filter miss: vault has items (total > 0) but filtered list is empty.
	allSecrets := []secretMetadataView{
		{Name: "REAL_SECRET", NamedReference: "@REAL_SECRET"},
	}
	filteredSecrets := []secretMetadataView{} // no matches

	// renderSecretListWithColor with the full list — just to confirm the
	// renderer uses the "N secrets available" lead, not the empty-vault lead.
	var fullOut bytes.Buffer
	if err := renderSecretListWithColor(&fullOut, allSecrets, ui.ColorOptions{}); err != nil {
		t.Fatalf("renderSecretListWithColor (full list): %v", err)
	}
	if strings.Contains(fullOut.String(), "No secrets stored") {
		t.Errorf("full-list render must not say 'No secrets stored'; got:\n%s", fullOut.String())
	}

	// The fixed rendering path: renderSecretSearchJSONOrHuman with total > 0
	// and an empty matched slice must say "no matches for" and must NOT say
	// "No secrets stored".
	const query = "xyz_no_match"
	var filteredOut bytes.Buffer
	if err := renderSecretSearchJSONOrHuman(context.Background(), &filteredOut, false, query, len(allSecrets), filteredSecrets, ui.ColorOptions{}); err != nil {
		t.Fatalf("renderSecretSearchJSONOrHuman (filter miss): %v", err)
	}
	got := filteredOut.String()
	if strings.Contains(strings.ToLower(got), "no secrets stored") {
		t.Errorf("filter-miss render must not say 'No secrets stored'; got:\n%s", got)
	}
	if !strings.Contains(strings.ToLower(got), "no matches") {
		t.Errorf("filter-miss render must say 'no matches'; got:\n%s", got)
	}
	if !strings.Contains(got, query) {
		t.Errorf("filter-miss render must reference the query %q; got:\n%s", query, got)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func searchPayloadKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func numericField(m map[string]any, key string) (float64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	f, ok := v.(float64)
	return f, ok
}
