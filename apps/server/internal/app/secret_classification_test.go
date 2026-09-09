package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"io"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestSecretClassifyOperatorMetadataAndProtectedDenial(t *testing.T) {
	lockAppSeams(t)
	h, token := setupAgentSafeSession(t)
	if _, err := h.GrantPlaintextUse(token, "API_TOKEN", store.PlaintextReveal, "user", store.GrantOnce, 0); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	args := []string{"secret", "classify", "API_TOKEN", "--classification", "configuration", "--json"}
	if err := Run(context.Background(), args, strings.NewReader("yes\n"), &out, io.Discard); err == nil || !strings.Contains(err.Error(), "local operator") {
		t.Fatalf("protected process classified item: %s %v", out.String(), err)
	}
	if !h.PlaintextGrantActive(token, "API_TOKEN", store.PlaintextReveal) {
		t.Fatal("classification consumed unrelated plaintext grant")
	}
	t.Setenv(envAgentSafeMode, "")
	t.Setenv(envSessionToken, "")
	t.Chdir(t.TempDir())
	out.Reset()
	if err := Run(context.Background(), args, nil, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["classification"] != "configuration" || strings.Contains(out.String(), "abc123") {
		t.Fatalf("bad classification output: %s", out.String())
	}
	for _, command := range []string{"get", "list", "search"} {
		cmd := []string{"secret", command, "--json"}
		if command != "list" {
			cmd = append(cmd, "API_TOKEN")
		}
		out.Reset()
		if err := Run(context.Background(), cmd, nil, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), `"classification":"configuration"`) || strings.Contains(out.String(), "abc123") {
			t.Fatalf("%s lost classification or exposed value: %s", command, out.String())
		}
	}
	out.Reset()
	if err := Run(context.Background(), []string{"secret", "classify", "API_TOKEN", "--classification", "configuration"}, nil, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "API_TOKEN: configuration") || strings.Contains(out.String(), "abc123") {
		t.Fatalf("classification human output: %s", out.String())
	}
	if err := Run(context.Background(), []string{"secret", "classify", "missing", "--classification", "configuration"}, nil, io.Discard, io.Discard); !errors.Is(err, store.ErrItemNotFound) {
		t.Fatalf("missing classification item: %v", err)
	}
	for _, invalid := range [][]string{{"secret", "classify", "API_TOKEN"}, {"secret", "classify", "API_TOKEN", "--classification", "public-id"}} {
		if err := Run(context.Background(), invalid, nil, io.Discard, io.Discard); err == nil {
			t.Fatal("invalid classification accepted")
		}
	}
}

func TestClassificationFailsClosedWhenPolicyLookupFails(t *testing.T) {
	lockAppSeams(t)
	oldManager := secretNewManagerFn
	t.Cleanup(func() { secretNewManagerFn = oldManager })
	want := errors.New("broker unavailable")
	secretNewManagerFn = func() (*runtime.Manager, error) { return nil, want }
	if err := enforceClassificationChange(context.Background(), nil, "TOKEN"); !errors.Is(err, want) {
		t.Fatalf("classification ignored policy failure: %v", err)
	}
}
