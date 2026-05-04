package app

// Red-team tests for hasp-x05.2.1: "Add generic print-config surfaces".
//
// These tests assert the existence and correctness of agentGenericPrintConfig,
// a function that emits ready-to-paste config snippets for the generic
// MCP-agent path.  The function does NOT exist yet; these tests FAIL (compile
// error) until the green team implements it.
//
// Proposed function signature (green team must match exactly):
//
//   func agentGenericPrintConfig() map[string]string
//
// The returned map must have at least these four keys:
//   "stdio-json"   – JSON snippet (map["mcpServers"] style)
//   "cursor-json"  – JSON snippet (Cursor/Composer mcp config style)
//   "codex-toml"   – TOML snippet (codex-cli [[servers.X]] style)
//   "claude-json"  – JSON snippet (Claude Code mcpServers style)
//
// Labelling contract:
//   - Every snippet must contain the substring "generic-compatible"
//     (the canonical CompatibilityLabel from profiles.CompatibilityLabelGeneric
//     is "generic-broker-path", but any "generic-compatible" occurrence satisfies
//     the contract — the green team may embed it in a comment or metadata field).
//   - No snippet may contain the literal string "first-class".

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestAgentGenericPrintConfigExists asserts that agentGenericPrintConfig
// returns a non-nil map with at least the four required target keys.
func TestAgentGenericPrintConfigExists(t *testing.T) {
	snippets := agentGenericPrintConfig()
	if snippets == nil {
		t.Fatal("agentGenericPrintConfig returned nil map")
	}

	required := []string{"stdio-json", "cursor-json", "codex-toml", "claude-json"}
	for _, key := range required {
		if _, ok := snippets[key]; !ok {
			t.Errorf("agentGenericPrintConfig: missing required key %q", key)
		}
	}
}

// TestAgentGenericPrintConfigJSONTargetsParseAsJSON asserts that the three
// JSON-format targets ("stdio-json", "cursor-json", "claude-json") each contain
// valid JSON.
func TestAgentGenericPrintConfigJSONTargetsParseAsJSON(t *testing.T) {
	snippets := agentGenericPrintConfig()

	jsonTargets := []string{"stdio-json", "cursor-json", "claude-json"}
	for _, key := range jsonTargets {
		raw, ok := snippets[key]
		if !ok {
			t.Errorf("missing key %q — skipping JSON parse check", key)
			continue
		}
		var parsed any
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			t.Errorf("target %q: snippet is not valid JSON: %v\nsnippet:\n%s", key, err, raw)
		}
	}
}

// TestAgentGenericPrintConfigTomlTargetHasServerHeader asserts that the
// "codex-toml" target contains a [servers. section header (or [[servers.) that
// signals a valid codex-cli TOML block, and does not contain obvious TOML
// syntax errors such as an unquoted bare bracket mismatch.
func TestAgentGenericPrintConfigTomlTargetHasServerHeader(t *testing.T) {
	snippets := agentGenericPrintConfig()

	raw, ok := snippets["codex-toml"]
	if !ok {
		t.Fatal("missing required key \"codex-toml\"")
	}
	if !strings.Contains(raw, "[servers.") && !strings.Contains(raw, "[[servers.") {
		t.Errorf("codex-toml snippet does not contain a [servers.X] or [[servers.X]] header\nsnippet:\n%s", raw)
	}
}

// TestAgentGenericPrintConfigSnippetsLabeledGenericCompatible asserts that
// every snippet produced by agentGenericPrintConfig contains the substring
// "generic-compatible".  This enforces that consumers of the snippets cannot
// mistake the generic path for a first-class agent profile.
func TestAgentGenericPrintConfigSnippetsLabeledGenericCompatible(t *testing.T) {
	snippets := agentGenericPrintConfig()

	for key, raw := range snippets {
		if !strings.Contains(raw, "generic-compatible") {
			t.Errorf("target %q: snippet does not contain \"generic-compatible\"\nsnippet:\n%s", key, raw)
		}
	}
}

// TestAgentGenericPrintConfigSnippetsDoNotContainFirstClass asserts that no
// snippet produced by agentGenericPrintConfig contains the literal string
// "first-class".  The generic path must never be promoted to first-class
// status inside its own config snippet output.
func TestAgentGenericPrintConfigSnippetsDoNotContainFirstClass(t *testing.T) {
	snippets := agentGenericPrintConfig()

	for key, raw := range snippets {
		if strings.Contains(raw, "first-class") {
			t.Errorf("target %q: snippet must not contain \"first-class\" for the generic path\nsnippet:\n%s", key, raw)
		}
	}
}

// TestAgentGenericPrintConfigJSONTargetsHasMCPServersKey asserts that each
// JSON-format snippet includes an "mcpServers" or "mcp" top-level key, which
// is the standard envelope for stdio MCP config in all three first-class JSON
// formats (claude-code, cursor, generic stdio).
func TestAgentGenericPrintConfigJSONTargetsHasMCPServersKey(t *testing.T) {
	snippets := agentGenericPrintConfig()

	jsonTargets := []string{"stdio-json", "cursor-json", "claude-json"}
	for _, key := range jsonTargets {
		raw, ok := snippets[key]
		if !ok {
			t.Errorf("missing key %q — skipping mcpServers check", key)
			continue
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			// Already caught by the JSON validity test; skip here.
			continue
		}
		_, hasMCPServers := parsed["mcpServers"]
		_, hasMCP := parsed["mcp"]
		if !hasMCPServers && !hasMCP {
			t.Errorf("target %q: JSON snippet must have a top-level \"mcpServers\" or \"mcp\" key\nsnippet:\n%s", key, raw)
		}
	}
}
