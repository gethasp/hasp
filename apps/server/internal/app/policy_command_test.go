package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func TestPolicyShowSetAndValidateCommandsUseDaemonPolicy(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)
	if err := runWithStarter(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter); err != nil {
		t.Fatalf("init: %v", err)
	}
	var initialOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"policy", "show", "--json"}, bytes.NewBuffer(nil), &initialOut, io.Discard, starter); err != nil {
		t.Fatalf("policy show initial: %v", err)
	}
	var initial runtime.PolicyResponse
	if err := json.Unmarshal(initialOut.Bytes(), &initial); err != nil {
		t.Fatalf("decode initial policy: %v\n%s", err, initialOut.String())
	}
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	policy := runtime.PolicyDocument{Version: initial.Version, Rules: []runtime.PolicyRule{{
		ID:       "allow-ci",
		Match:    runtime.PolicyMatch{Consumer: "ci-runner", Secret: "prod/db/password", Scope: "read"},
		Decision: "allow",
		TTLS:     900,
	}}}
	writePolicyFile(t, policyPath, policy)
	var setOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"policy", "set", "--file", policyPath, "--json"}, bytes.NewBuffer(nil), &setOut, io.Discard, starter); err != nil {
		t.Fatalf("policy set: %v", err)
	}
	var updated runtime.PolicyResponse
	if err := json.Unmarshal(setOut.Bytes(), &updated); err != nil {
		t.Fatalf("decode updated policy: %v\n%s", err, setOut.String())
	}
	if updated.Version == initial.Version || updated.UpdatedBy != "cli" || len(updated.Rules) != 1 {
		t.Fatalf("updated policy = %+v", updated)
	}
	if err := runWithStarter(context.Background(), []string{"policy", "set", "--file", policyPath, "--json"}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter); err == nil {
		t.Fatal("expected stale policy set to fail")
	}
	if err := runWithStarter(context.Background(), []string{"policy", "set", "--file", policyPath, "--force", "--json"}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter); err != nil {
		t.Fatalf("policy set --force: %v", err)
	}
	badPath := filepath.Join(t.TempDir(), "bad-policy.json")
	bad := runtime.PolicyDocument{Rules: []runtime.PolicyRule{
		{ID: "allow-ci", Match: runtime.PolicyMatch{Consumer: "ci-runner", Secret: "prod/db/password", Scope: "read"}, Decision: "allow"},
		{ID: "deny-ci", Match: runtime.PolicyMatch{Consumer: "ci-runner", Secret: "prod/db/password", Scope: "read"}, Decision: "deny"},
	}}
	writePolicyFile(t, badPath, bad)
	var before bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"policy", "show", "--json"}, bytes.NewBuffer(nil), &before, io.Discard, starter); err != nil {
		t.Fatalf("policy show before validate: %v", err)
	}
	if err := runWithStarter(context.Background(), []string{"policy", "validate", "--file", badPath, "--json"}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter); err == nil {
		t.Fatal("expected policy validate to reject conflict")
	}
	var after bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"policy", "show", "--json"}, bytes.NewBuffer(nil), &after, io.Discard, starter); err != nil {
		t.Fatalf("policy show after validate: %v", err)
	}
	if !bytes.Equal(normalizeJSONBytes(t, before.Bytes()), normalizeJSONBytes(t, after.Bytes())) {
		t.Fatalf("policy validate changed persisted policy\nbefore=%s\nafter=%s", before.String(), after.String())
	}
}

func TestPolicyHelpAndCompletionAreWired(t *testing.T) {
	lockAppSeams(t)
	var help bytes.Buffer
	if err := Run(context.Background(), []string{"help", "policy"}, bytes.NewBuffer(nil), &help, io.Discard); err != nil {
		t.Fatalf("hasp help policy: %v", err)
	}
	if !strings.Contains(help.String(), "show") || !strings.Contains(help.String(), "validate") || !strings.Contains(help.String(), "set") {
		t.Fatalf("policy help missing subcommands:\n%s", help.String())
	}
	got := Complete([]string{"policy"}, CompletionOptions{})
	for _, want := range []string{"show", "set", "validate"} {
		if !slices.Contains(got, want) {
			t.Fatalf("policy completions missing %q: %v", want, got)
		}
	}
}

func writePolicyFile(t *testing.T, path string, policy runtime.PolicyDocument) {
	t.Helper()
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal policy file: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
}

func normalizeJSONBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode json for normalization: %v\n%s", err, data)
	}
	out, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("encode normalized json: %v", err)
	}
	return out
}
