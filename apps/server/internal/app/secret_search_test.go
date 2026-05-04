package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// hasp-yxsx: Today operators must `secret list | grep` to find a name —
// fine in a shell, brittle in JSON pipelines. `secret search <substr>`
// case-insensitively filters by item name only and never touches the
// value, so it is safe to run inside an agent context.

func TestSecretSearchCommandFiltersByNameCaseInsensitive(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	for _, name := range []string{"OPENAI_API_KEY", "STRIPE_SECRET", "github_token"} {
		if err := Run(context.Background(), []string{"secret", "add", "--from-stdin", "--vault-only", name}, bytes.NewBufferString("redacted-value"), io.Discard, io.Discard); err != nil {
			t.Fatalf("secret add %s: %v", name, err)
		}
	}

	var out bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "search", "--json", "api"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("secret search: %v", err)
	}
	var payload struct {
		Secrets []map[string]any `json:"secrets"`
	}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode search output: %v", err)
	}
	if len(payload.Secrets) != 1 {
		t.Fatalf("expected 1 match for 'api', got %d: %v", len(payload.Secrets), payload.Secrets)
	}
	if name, _ := payload.Secrets[0]["name"].(string); name != "OPENAI_API_KEY" {
		t.Fatalf("expected OPENAI_API_KEY, got %q", name)
	}
}

func TestSecretSearchCommandRequiresQueryString(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "search"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected missing query argument to fail")
	}
}

func TestSecretSearchCommandHumanRendersMatchedNames(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--from-stdin", "--vault-only", "AWS_SESSION_TOKEN"}, bytes.NewBufferString("redacted-value"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}

	var out bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "search", "session"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("secret search: %v", err)
	}
	if !strings.Contains(out.String(), "AWS_SESSION_TOKEN") {
		t.Fatalf("expected AWS_SESSION_TOKEN in human output, got %q", out.String())
	}
}
