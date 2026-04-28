package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"
)

func TestVersionAndBootstrapProfilesJSONBranches(t *testing.T) {
	lockAppSeams(t)

	var out bytes.Buffer
	if err := versionCommand(context.Background(), []string{"--json"}, &out); err != nil {
		t.Fatalf("versionCommand json: %v", err)
	}
	var versionPayload map[string]any
	if err := json.Unmarshal(out.Bytes(), &versionPayload); err != nil {
		t.Fatalf("decode version payload: %v", err)
	}
	if versionPayload["version"] == "" {
		t.Fatalf("expected version payload, got %q", out.String())
	}
	if err := versionCommand(context.Background(), []string{"extra"}, &out); err == nil {
		t.Fatal("expected version usage failure")
	}

	out.Reset()
	if err := bootstrapProfilesCommand(context.Background(), []string{"--json"}, &out); err != nil {
		t.Fatalf("bootstrapProfilesCommand json: %v", err)
	}
	var profilesPayload map[string]any
	if err := json.Unmarshal(out.Bytes(), &profilesPayload); err != nil {
		t.Fatalf("decode profiles payload: %v", err)
	}
	if _, ok := profilesPayload["profiles"]; !ok {
		t.Fatalf("expected profiles payload, got %q", out.String())
	}
	if err := bootstrapProfilesCommand(context.Background(), []string{"extra"}, &out); err == nil {
		t.Fatal("expected bootstrap profiles usage failure")
	}

	if err := runWithStarter(context.Background(), []string{"version", "--json"}, bytes.NewBuffer(nil), &out, &out, &fakeStarter{}); err != nil {
		t.Fatalf("runWithStarter version json: %v", err)
	}
}

func TestRunWithStarterGetAndTUIJSONBranches(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	// Use --from-stdin to avoid argv plaintext exposure (NAME=VALUE form is now rejected).
	if err := Run(context.Background(), []string{"secret", "add", "--project-root", projectRoot, "--from-stdin", "--expose=always", "API_TOKEN"}, bytes.NewBufferString("abc123\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}

	var out bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"secret", "get", "--json", "API_TOKEN"}, bytes.NewBuffer(nil), &out, &out, &fakeStarter{}); err != nil {
		t.Fatalf("runWithStarter secret get json: %v", err)
	}
	var getPayload map[string]any
	if err := json.Unmarshal(out.Bytes(), &getPayload); err != nil {
		t.Fatalf("decode get payload: %v", err)
	}
	secretPayload, _ := getPayload["secret"].(map[string]any)
	if secretPayload["name"] != "API_TOKEN" {
		t.Fatalf("unexpected get payload %q", out.String())
	}

	out.Reset()
	if err := tuiCommand(context.Background(), []string{"--json", "--project-root", projectRoot}, &out, io.Discard); err != nil {
		t.Fatalf("tuiCommand json: %v", err)
	}
	var tuiPayload map[string]any
	if err := json.Unmarshal(out.Bytes(), &tuiPayload); err != nil {
		t.Fatalf("decode tui payload: %v", err)
	}
	if tuiPayload["binding"] == nil || tuiPayload["project_root"] == nil {
		t.Fatalf("unexpected tui payload %q", out.String())
	}
	if root, _ := tuiPayload["project_root"].(string); root == "" || filepath.Base(root) != filepath.Base(projectRoot) {
		t.Fatalf("unexpected tui project root %q", root)
	}
}
