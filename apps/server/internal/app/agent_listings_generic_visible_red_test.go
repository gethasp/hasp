package app

// Red-team tests for hasp-x05.2.2: "Make generic-compatible visible in CLI/operator listings".
//
// These tests assert that the CLI/operator surfaces expose the generic-compatible
// path with enough detail for operators to discover and use it.  Several of the
// symbols they reference do NOT exist yet; these tests MUST fail (compile error
// or runtime assertion) until the green team implements them.
//
// Pinned contracts the green team must satisfy:
//
//  1. agentSupportedProfileView gains four new fields:
//       SetupCommand      string            `json:"setup_command"`
//       DoctorCommand     string            `json:"doctor_command"`
//       FirstProofCommand string            `json:"first_proof_command"`
//       PrintConfig       map[string]string `json:"print_config"`
//
//  2. genericAgentSupportedProfileView() populates all four fields:
//       - SetupCommand      starts with "hasp setup" or "hasp bootstrap"
//       - DoctorCommand     starts with "hasp bootstrap doctor"
//       - FirstProofCommand starts with "hasp run"
//       - PrintConfig       == agentGenericPrintConfig()  (all four keys)
//
//  3. "hasp agent list-supported --json" output includes an entry whose
//     profile == "generic-compatible" (support_tier field) AND that entry
//     carries non-empty setup_command, doctor_command, first_proof_command,
//     and a print_config object with keys stdio-json/cursor-json/codex-toml/claude-json.
//
//  4. "hasp agent list-supported" human output contains the literal string
//     "generic-compatible".
//
//  5. "hasp bootstrap doctor generic" human output:
//       - mentions "generic-compatible"
//       - does NOT contain the phrase "first-class" immediately adjacent to
//         the word "generic" (negative assertion; guards against over-claiming).
//
//  6. "hasp bootstrap print-config generic-compatible" is a valid subcommand that:
//       - by default (or --format stdio-json) outputs the stdio-json snippet
//       - with --format cursor-json    outputs the cursor-json snippet
//       - with --format codex-toml     outputs the codex-toml snippet
//       - with --format claude-json    outputs the claude-json snippet
//     Each output must contain "generic-compatible" and must NOT contain "first-class".
//
//     If bootstrapPrintConfigCommand does not yet exist, this file pins its
//     required shape:
//       func bootstrapPrintConfigCommand(args []string, stdout io.Writer) error
//     dispatched from bootstrapCommandWithInput via:
//       case "print-config":
//           return bootstrapPrintConfigCommand(args[1:], stdout)

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test 1 — JSON listing: generic-compatible entry has all required fields
// ---------------------------------------------------------------------------

// TestAgentListingsGenericVisibleInJSON asserts that "hasp agent list-supported --json"
// returns a profiles array entry with support_tier == "generic-compatible" AND
// non-empty setup_command, doctor_command, first_proof_command, and a
// print_config map with the four canonical snippet keys.
func TestAgentListingsGenericVisibleInJSON(t *testing.T) {
	var out bytes.Buffer
	if err := runWithStarter(context.Background(),
		[]string{"agent", "list-supported", "--json"},
		bytes.NewBuffer(nil), &out, io.Discard,
		&fakeStarter{},
	); err != nil {
		t.Fatalf("agent list-supported --json: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode agent list-supported output: %v", err)
	}

	profileValues, ok := payload["profiles"].([]any)
	if !ok {
		t.Fatalf("expected profiles array, got %T", payload["profiles"])
	}

	var genericEntry map[string]any
	for _, raw := range profileValues {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if entry["support_tier"] == "generic-compatible" {
			genericEntry = entry
			break
		}
	}
	if genericEntry == nil {
		t.Fatalf("agent list-supported --json: no entry with support_tier==\"generic-compatible\" found; profiles=%s", out.String())
	}

	// setup_command must be non-empty and look like "hasp setup ..." or "hasp bootstrap ..."
	setupCmd, _ := genericEntry["setup_command"].(string)
	if strings.TrimSpace(setupCmd) == "" {
		t.Errorf("generic-compatible entry: setup_command is missing or empty, got %q", setupCmd)
	}
	if !strings.HasPrefix(setupCmd, "hasp setup") && !strings.HasPrefix(setupCmd, "hasp bootstrap") {
		t.Errorf("generic-compatible entry: setup_command %q does not start with 'hasp setup' or 'hasp bootstrap'", setupCmd)
	}

	// doctor_command must be non-empty and look like "hasp bootstrap doctor ..."
	doctorCmd, _ := genericEntry["doctor_command"].(string)
	if strings.TrimSpace(doctorCmd) == "" {
		t.Errorf("generic-compatible entry: doctor_command is missing or empty, got %q", doctorCmd)
	}
	if !strings.HasPrefix(doctorCmd, "hasp bootstrap doctor") {
		t.Errorf("generic-compatible entry: doctor_command %q does not start with 'hasp bootstrap doctor'", doctorCmd)
	}

	// first_proof_command must be non-empty and look like "hasp run ..."
	firstProofCmd, _ := genericEntry["first_proof_command"].(string)
	if strings.TrimSpace(firstProofCmd) == "" {
		t.Errorf("generic-compatible entry: first_proof_command is missing or empty, got %q", firstProofCmd)
	}
	if !strings.HasPrefix(firstProofCmd, "hasp run") {
		t.Errorf("generic-compatible entry: first_proof_command %q does not start with 'hasp run'", firstProofCmd)
	}

	// print_config must be a map with the four canonical snippet keys
	printConfigRaw, hasPrintConfig := genericEntry["print_config"]
	if !hasPrintConfig || printConfigRaw == nil {
		t.Fatalf("generic-compatible entry: print_config field is missing; entry=%v", genericEntry)
	}
	printConfig, ok := printConfigRaw.(map[string]any)
	if !ok {
		t.Fatalf("generic-compatible entry: print_config is not a map, got %T", printConfigRaw)
	}
	for _, key := range []string{"stdio-json", "cursor-json", "codex-toml", "claude-json"} {
		if _, ok := printConfig[key]; !ok {
			t.Errorf("generic-compatible entry: print_config missing key %q; keys present: %v", key, printConfig)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 2 — Human listing: "generic-compatible" is visible
// ---------------------------------------------------------------------------

// TestAgentListingsGenericVisibleInHuman asserts that the human-readable output
// of "hasp agent list-supported" contains the literal string "generic-compatible".
func TestAgentListingsGenericVisibleInHuman(t *testing.T) {
	var out bytes.Buffer
	if err := runWithStarter(context.Background(),
		[]string{"agent", "list-supported"},
		bytes.NewBuffer(nil), &out, io.Discard,
		&fakeStarter{},
	); err != nil {
		t.Fatalf("agent list-supported (human): %v", err)
	}
	if !strings.Contains(out.String(), "generic-compatible") {
		t.Fatalf("agent list-supported human output does not contain 'generic-compatible';\noutput:\n%s", out.String())
	}
}

// ---------------------------------------------------------------------------
// Test 3 — bootstrap doctor generic: mentions generic-compatible, not first-class
// ---------------------------------------------------------------------------

// TestBootstrapDoctorGenericMentionsGenericCompatible asserts that
// "hasp bootstrap doctor generic" human output:
//   - contains the string "generic-compatible"
//   - does NOT contain "first-class" adjacent to "generic" (no over-claiming)
//
// The negative assertion uses a proximity heuristic: if the word "first-class"
// appears anywhere within 60 bytes of "generic" in the output, the test fails.
func TestBootstrapDoctorGenericMentionsGenericCompatible(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	var out bytes.Buffer
	// bootstrapDoctorCommand dispatches via "generic" positional arg.
	if err := bootstrapDoctorCommand(context.Background(),
		[]string{"generic", "--project-root", t.TempDir()},
		bytes.NewBuffer(nil), &out,
	); err != nil {
		t.Fatalf("bootstrap doctor generic: %v", err)
	}

	text := out.String()
	if !strings.Contains(text, "generic-compatible") {
		t.Errorf("bootstrap doctor generic: output does not mention 'generic-compatible';\noutput:\n%s", text)
	}

	// Negative assertion: "first-class" must not appear adjacent to "generic".
	lower := strings.ToLower(text)
	for idx := 0; idx < len(lower); idx++ {
		if lower[idx:idx+min60(lower, idx, "generic")] == "generic"[:min60(lower, idx, "generic")] {
			start := idx
			windowStart := start - 30
			if windowStart < 0 {
				windowStart = 0
			}
			windowEnd := start + 60
			if windowEnd > len(lower) {
				windowEnd = len(lower)
			}
			window := lower[windowStart:windowEnd]
			if strings.Contains(window, "first-class") {
				t.Errorf("bootstrap doctor generic: 'first-class' found adjacent to 'generic' in output (over-claiming guard);\ncontext: %q\nfull output:\n%s", window, text)
				break
			}
		}
	}
}

// min60 is a tiny helper for the sliding-window approach above.
// It returns the smaller of 7 (len("generic")) or the remaining bytes in s from idx.
func min60(s string, idx int, needle string) int {
	rem := len(s) - idx
	n := len(needle)
	if rem < n {
		return rem
	}
	return n
}

// ---------------------------------------------------------------------------
// Test 4 — bootstrap print-config generic-compatible: outputs snippets
// ---------------------------------------------------------------------------

// TestBootstrapPrintConfigGenericDefaultsToStdioJSON asserts that
// "hasp bootstrap print-config generic-compatible" (no --format flag) outputs
// the stdio-json snippet by default.
//
// This pins bootstrapPrintConfigCommand — the green team MUST add:
//   - A "print-config" case in bootstrapCommandWithInput
//   - func bootstrapPrintConfigCommand(args []string, stdout io.Writer) error
//     that accepts an optional --format flag defaulting to "stdio-json".
func TestBootstrapPrintConfigGenericDefaultsToStdioJSON(t *testing.T) {
	var out bytes.Buffer
	// bootstrapPrintConfigCommand does not exist yet — this causes a compile error.
	if err := bootstrapPrintConfigCommand([]string{"generic-compatible"}, &out); err != nil {
		t.Fatalf("bootstrap print-config generic-compatible: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "generic-compatible") {
		t.Errorf("bootstrap print-config generic-compatible: output does not contain 'generic-compatible';\noutput:\n%s", text)
	}
	if strings.Contains(text, "first-class") {
		t.Errorf("bootstrap print-config generic-compatible: output must not contain 'first-class';\noutput:\n%s", text)
	}
	// Default output should be a JSON object (stdio-json format).
	var parsed any
	if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &parsed); err != nil {
		t.Errorf("bootstrap print-config generic-compatible default output is not valid JSON: %v\noutput:\n%s", err, text)
	}
}

// TestBootstrapPrintConfigGenericFormatFlags asserts that --format selects
// the correct snippet for each of the four canonical formats.
func TestBootstrapPrintConfigGenericFormatFlags(t *testing.T) {
	snippets := agentGenericPrintConfig()

	cases := []struct {
		format  string
		snippet string
	}{
		{"stdio-json", snippets["stdio-json"]},
		{"cursor-json", snippets["cursor-json"]},
		{"codex-toml", snippets["codex-toml"]},
		{"claude-json", snippets["claude-json"]},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.format, func(t *testing.T) {
			var out bytes.Buffer
			// bootstrapPrintConfigCommand does not exist yet — compile error.
			if err := bootstrapPrintConfigCommand(
				[]string{"generic-compatible", "--format", tc.format},
				&out,
			); err != nil {
				t.Fatalf("bootstrap print-config generic-compatible --format %s: %v", tc.format, err)
			}
			text := out.String()
			if !strings.Contains(text, "generic-compatible") {
				t.Errorf("format %q: output does not contain 'generic-compatible';\noutput:\n%s", tc.format, text)
			}
			if strings.Contains(text, "first-class") {
				t.Errorf("format %q: output must not contain 'first-class';\noutput:\n%s", tc.format, text)
			}
			// The output should contain the same content as the canonical snippet.
			if tc.snippet != "" && !strings.Contains(text, strings.TrimSpace(tc.snippet)[:20]) {
				t.Errorf("format %q: output does not resemble the canonical snippet;\nexpected prefix of:\n%s\ngot:\n%s",
					tc.format, tc.snippet, text)
			}
		})
	}
}

// TestBootstrapPrintConfigGenericViaRun asserts that the CLI dispatcher
// (bootstrapCommandWithInput) routes "print-config" to bootstrapPrintConfigCommand.
// This test also fails if the "print-config" case is missing from the switch.
func TestBootstrapPrintConfigGenericViaRun(t *testing.T) {
	var out bytes.Buffer
	// bootstrapCommandWithInput must route "print-config" to a handler.
	// If the case is missing, this will hit the parseBootstrapOptions usage error.
	// We use the real bootstrapVerification signature (profiles.Profile, bool).
	if err := bootstrapCommandWithInput(context.Background(),
		[]string{"print-config", "generic-compatible"},
		nil, &out,
		bootstrapVerification,
	); err != nil {
		t.Fatalf("hasp bootstrap print-config generic-compatible via dispatcher: %v", err)
	}
	if !strings.Contains(out.String(), "generic-compatible") {
		t.Fatalf("hasp bootstrap print-config generic-compatible: output does not contain 'generic-compatible';\noutput:\n%s", out.String())
	}
}
