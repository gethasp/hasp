package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/profiles"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// Helpers repoRootForAppTests and readRepoFileForAppTests live in
// private_docs_red_test.go so the public export can keep the tests in
// this file while dropping the repo-root doc assertions.

func TestSetupNextStepsDescribeConcreteFirstProof(t *testing.T) {
	steps := setupNextSteps(
		"/tmp/repo",
		store.Binding{Aliases: map[string]string{"secret_01": "API_TOKEN"}},
		"/tmp/.hasp",
		"disabled",
		"",
		true,
		true,
	)

	joined := strings.Join(steps, "\n")
	for _, want := range []string{
		`verify MCP with: printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | hasp mcp`,
		`review the repo binding with: hasp project status --project-root "/tmp/repo"`,
		`run a brokered proof command: hasp run --project-root "/tmp/repo" --env HASP_SETUP_PROOF=secret_01 --grant-project window --grant-secret session --grant-window 15m -- sh -c 'test -n "$HASP_SETUP_PROOF"'`,
		`saved CLI config keeps HASP_HOME at /tmp/.hasp`,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("setup next steps missing %q in %q", want, joined)
		}
	}
}

func TestBootstrapProfilesExposeGenericCompatibilityFirstProofSurface(t *testing.T) {
	result, err := bootstrapProfileListing(profiles.LoadCatalog, profiles.LoadReleaseGates)
	if err != nil {
		t.Fatalf("bootstrapProfileListing: %v", err)
	}

	genericPath, ok := result["generic_path"].(map[string]any)
	if !ok {
		t.Fatalf("expected generic_path object, got %#v", result["generic_path"])
	}
	if genericPath["support_tier"] != profiles.SupportTierGenericCompatible {
		t.Fatalf("unexpected generic support tier: %#v", genericPath)
	}
	if genericPath["compatibility_label"] != profiles.CompatibilityLabelGeneric || genericPath["first_class"] != false {
		t.Fatalf("unexpected generic proof surface: %#v", genericPath)
	}

	command, ok := genericPath["command"].([]string)
	if !ok {
		t.Fatalf("expected generic command slice, got %#v", genericPath["command"])
	}
	if len(command) != 2 || command[0] != "hasp" || command[1] != "mcp" {
		t.Fatalf("unexpected generic command: %#v", command)
	}
	if genericPath["doctor_command"] != "hasp bootstrap doctor generic --project-root <repo>" {
		t.Fatalf("unexpected generic doctor command: %#v", genericPath["doctor_command"])
	}

	notes, ok := genericPath["notes"].([]string)
	if !ok {
		t.Fatalf("expected generic notes slice, got %#v", genericPath["notes"])
	}
	if len(notes) < 2 {
		t.Fatalf("expected generic notes, got %#v", notes)
	}
	if !strings.Contains(notes[0], "first-class support") || !strings.Contains(notes[1], "stdio MCP") {
		t.Fatalf("unexpected generic notes: %#v", notes)
	}
	if genericPath["setup_command"] == "" || genericPath["first_proof_command"] == "" {
		t.Fatalf("expected generic setup and first proof commands, got %#v", genericPath)
	}
}

func TestBootstrapProfilesHumanSummaryIncludesGenericFirstProof(t *testing.T) {
	var out bytes.Buffer
	if err := renderBootstrapProfilesSummary(&out, map[string]any{
		"profiles":     []map[string]any{{"id": "claude-code", "support_tier": "first-class-shipped", "transport": "mcp-stdio"}},
		"generic_path": genericCompatibilitySurface(),
	}); err != nil {
		t.Fatalf("renderBootstrapProfilesSummary: %v", err)
	}
	text := out.String()
	for _, want := range []string{"Generic-compatible first proof", "setup:", "first proof:"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in %q", want, text)
		}
	}
}

func TestBootstrapProfilesHumanSummarySkipsMissingGenericProofFields(t *testing.T) {
	var out bytes.Buffer
	if err := renderBootstrapProfilesSummary(&out, map[string]any{
		"profiles": []any{"skip", map[string]any{"id": "claude-code", "support_tier": "first-class-shipped", "transport": "mcp-stdio"}},
		"generic_path": map[string]any{
			"id":           "generic",
			"support_tier": profiles.SupportTierGenericCompatible,
			"transport":    "mcp-stdio",
		},
	}); err != nil {
		t.Fatalf("renderBootstrapProfilesSummary without proof commands: %v", err)
	}
	text := out.String()
	if strings.Contains(text, "setup:") || strings.Contains(text, "first proof:") {
		t.Fatalf("expected missing generic commands to stay hidden, got %q", text)
	}
}

func TestAgentListSupportedIncludesGenericCompatibleProofSurface(t *testing.T) {
	var out bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"agent", "list-supported", "--json"}, bytes.NewBuffer(nil), &out, bytes.NewBuffer(nil), &fakeStarter{}); err != nil {
		t.Fatalf("agent list-supported --json: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode list-supported output: %v", err)
	}
	profileValues, ok := payload["profiles"].([]any)
	if !ok {
		t.Fatalf("expected profiles array, got %#v", payload["profiles"])
	}
	for _, raw := range profileValues {
		profile, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("expected profile object, got %#v", raw)
		}
		if profile["support_tier"] == profiles.SupportTierGenericCompatible {
			return
		}
	}

	t.Fatalf("expected agent list-supported output to include a generic-compatible proof surface because help advertises shipped/generic support proof; got %s", out.String())
}

func TestSetupProofHelpersCoverNonHappyPaths(t *testing.T) {
	result, err := setupVerifyBrokeredProof(context.Background(), "", nil)
	if err != nil || result["reason"] != "no project root" {
		t.Fatalf("expected no-project-root result, got %#v err=%v", result, err)
	}
	result, err = setupVerifyBrokeredProof(context.Background(), "/tmp/repo", nil)
	if err != nil || result["reason"] != "no brokered reference available yet" {
		t.Fatalf("expected no-reference result, got %#v err=%v", result, err)
	}

	lockAppSeams(t)
	origStarter := newRuntimeStarterFn
	t.Cleanup(func() { newRuntimeStarterFn = origStarter })
	newRuntimeStarterFn = func() (*runtimeStarter, error) { return nil, errors.New("starter fail") }
	result, err = setupVerifyBrokeredProof(context.Background(), "/tmp/repo", []store.VisibleReference{{Alias: "secret_01"}})
	if err != nil || result["ready"] != true || result["reference"] != "secret_01" {
		t.Fatalf("expected brokered proof to stay surface-only, got %#v err=%v", result, err)
	}

	if ref := setupFirstProofReference(nil); ref != "" {
		t.Fatalf("expected empty proof ref, got %q", ref)
	}
	if ref := setupFirstProofReference([]store.VisibleReference{{Alias: "secret_01"}}); ref != "secret_01" {
		t.Fatalf("expected alias proof ref, got %q", ref)
	}
	if ref := setupFirstProofReference([]store.VisibleReference{{Alias: "secret_01", NamedReference: "@API_TOKEN"}}); ref != "@API_TOKEN" {
		t.Fatalf("expected named proof ref, got %q", ref)
	}
	if ref := setupFirstProofReferenceFromAliases(map[string]string{"secret_02": "B", "secret_01": "A"}); ref != "secret_01" {
		t.Fatalf("expected sorted alias proof ref, got %q", ref)
	}
	if ref := setupFirstProofReferenceFromAliases(nil); ref != "" {
		t.Fatalf("expected empty alias proof ref, got %q", ref)
	}
}
