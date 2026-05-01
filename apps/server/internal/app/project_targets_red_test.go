package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectRequirementsJSONDoesNotExecuteTargetsOrExposeValues(t *testing.T) {
	lockAppSeams(t)
	projectRoot, secretValue, sentinel := setupProjectTargetManifestFixture(t)

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"project", "requirements", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("project requirements --json: %v", err)
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatalf("project requirements executed a target command and created %s", sentinel)
	}
	if strings.Contains(stdout.String(), secretValue) {
		t.Fatalf("project requirements exposed a secret value: %s", stdout.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("project requirements must return JSON: %v\nbody=%s", err, stdout.String())
	}
	if _, ok := payload["requirements"]; !ok {
		t.Fatalf("project requirements JSON missing requirements field: %+v", payload)
	}
}

func TestProjectRequirementsReportsPresenceAndSuggestionsWithoutValues(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	secretValue := "sk-present-fixture-secret"

	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "OPENAI_API_KEY", "--value", secretValue}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set present secret: %v", err)
	}
	manifest := `{
  "version": "v1",
  "references": [
    {"alias": "secret_01", "item": "OPENAI_API_KEY"},
    {"alias": "secret_02", "item": "DATABASE_URL"}
  ],
  "requirements": [
    {"ref": "@OPENAI_API_KEY", "kind": "kv", "classification": "secret", "required": true},
    {"ref": "@DATABASE_URL", "kind": "kv", "classification": "secret", "required": true}
  ],
  "targets": [
    {
      "name": "server.dev",
      "root": ".",
      "delivery": [
        {"as": "env", "name": "OPENAI_API_KEY", "ref": "@OPENAI_API_KEY"},
        {"as": "env", "name": "DATABASE_URL", "ref": "@DATABASE_URL"}
      ]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(projectRoot, ".hasp.manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"project", "requirements", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("project requirements --json: %v", err)
	}
	if strings.Contains(stdout.String(), secretValue) {
		t.Fatalf("project requirements exposed a secret value: %s", stdout.String())
	}
	var payload struct {
		Requirements []struct {
			Ref              string `json:"ref"`
			Present          bool   `json:"present"`
			Exposed          bool   `json:"exposed"`
			VaultAvailable   bool   `json:"vault_available"`
			SuggestedCommand string `json:"suggested_command"`
		} `json:"requirements"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode project requirements payload: %v\nbody=%s", err, stdout.String())
	}
	byRef := map[string]struct {
		Present          bool
		Exposed          bool
		VaultAvailable   bool
		SuggestedCommand string
	}{}
	for _, req := range payload.Requirements {
		byRef[req.Ref] = struct {
			Present          bool
			Exposed          bool
			VaultAvailable   bool
			SuggestedCommand string
		}{req.Present, req.Exposed, req.VaultAvailable, req.SuggestedCommand}
	}
	if got := byRef["@OPENAI_API_KEY"]; !got.Present || !got.Exposed || !got.VaultAvailable || got.SuggestedCommand != "" {
		t.Fatalf("unexpected present requirement status: %+v", got)
	}
	if got := byRef["@DATABASE_URL"]; got.Present || got.Exposed || !got.VaultAvailable || !strings.Contains(got.SuggestedCommand, "hasp secret add DATABASE_URL") {
		t.Fatalf("unexpected missing requirement status: %+v", got)
	}

	stdout.Reset()
	if err := Run(context.Background(), []string{"project", "requirements", "--project-root", projectRoot}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("project requirements human: %v", err)
	}
	human := stdout.String()
	if strings.Contains(human, secretValue) || !strings.Contains(human, "hasp secret add DATABASE_URL") {
		t.Fatalf("human requirements output missing suggestion or leaked value: %s", human)
	}
}

func TestProjectTargetsJSONDoesNotExecuteTargetsOrExposeCommands(t *testing.T) {
	lockAppSeams(t)
	projectRoot, secretValue, sentinel := setupProjectTargetManifestFixture(t)

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"project", "targets", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("project targets --json: %v", err)
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatalf("project targets executed a target command and created %s", sentinel)
	}
	body := stdout.String()
	if strings.Contains(body, secretValue) {
		t.Fatalf("project targets exposed a secret value: %s", body)
	}
	if strings.Contains(body, "touch "+sentinel) {
		t.Fatalf("project targets exposed repo-controlled command details: %s", body)
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("project targets must return JSON: %v\nbody=%s", err, body)
	}
	if _, ok := payload["targets"]; !ok {
		t.Fatalf("project targets JSON missing targets field: %+v", payload)
	}
}

func TestProjectExamplesCheckDoesNotExecuteTargetsOrWriteExampleFiles(t *testing.T) {
	lockAppSeams(t)
	projectRoot, secretValue, sentinel := setupProjectTargetManifestFixture(t)
	examplePath := filepath.Join(projectRoot, "apps", "server", ".env.example")

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"project", "examples", "--check", "--project-root", projectRoot, "--target", "server.dev"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("project examples --check: %v", err)
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatalf("project examples --check executed a target command and created %s", sentinel)
	}
	if _, err := os.Stat(examplePath); err == nil {
		t.Fatalf("project examples --check wrote %s during a read-only check", examplePath)
	}
	if strings.Contains(stdout.String(), secretValue) {
		t.Fatalf("project examples --check exposed a secret value: %s", stdout.String())
	}
}

func TestProjectDoctorJSONUsesSafeDiagnosticFields(t *testing.T) {
	lockAppSeams(t)
	projectRoot, secretValue, sentinel := setupProjectTargetManifestFixture(t)

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"project", "doctor", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("project doctor --json: %v", err)
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatalf("project doctor executed a target command and created %s", sentinel)
	}
	body := stdout.String()
	for _, forbidden := range []string{secretValue, "touch " + sentinel, "socket", "endpoint", "command"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("project doctor --json exposed forbidden content %q in %s", forbidden, body)
		}
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("project doctor must return JSON: %v\nbody=%s", err, body)
	}
	diagnostics, ok := payload["diagnostics"].([]any)
	if !ok {
		t.Fatalf("project doctor JSON missing diagnostics array: %+v", payload)
	}
	for _, entry := range diagnostics {
		diag, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("diagnostic entry must be an object, got %+v", entry)
		}
		for key := range diag {
			switch key {
			case "code", "severity", "target", "ref", "kind", "classification", "present", "exposed", "ignored", "stale":
			default:
				t.Fatalf("project doctor JSON exposed non-allowlisted key %q in %+v", key, diag)
			}
		}
	}
}

func TestProjectDoctorReportsTargetSafetyDiagnostics(t *testing.T) {
	projectRoot, _ := setupTargetRuntimeFixture(t)
	scriptPath := filepath.Join(projectRoot, "apps", "server", "bin", "dev")
	if err := os.MkdirAll(filepath.Dir(scriptPath), 0o755); err != nil {
		t.Fatalf("mkdir script dir: %v", err)
	}
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, ".gitignore"), nil, 0o600); err != nil {
		t.Fatalf("clear gitignore: %v", err)
	}
	manifest := `{
  "version": "v1",
  "references": [
    {"alias": "secret_01", "item": "OPENAI_API_KEY"},
    {"alias": "config_01", "item": "API_BASE_URL"},
    {"alias": "file_01", "item": "GOOGLE_SERVICE_ACCOUNT"}
  ],
  "requirements": [
    {"ref": "@OPENAI_API_KEY", "kind": "kv", "classification": "secret", "required": true},
    {"ref": "@API_BASE_URL", "kind": "kv", "classification": "secret", "required": true},
    {"ref": "@GOOGLE_SERVICE_ACCOUNT", "kind": "kv", "classification": "secret", "required": true}
  ],
  "targets": [
    {
      "name": "server.dev",
      "root": "apps/server",
      "command": ["./bin/dev"],
      "delivery": [{"as": "env", "name": "OPENAI_API_KEY", "ref": "@OPENAI_API_KEY"}]
    },
    {
      "name": "release.sign",
      "root": ".",
      "command": ["hasp-missing-doctor-command"],
      "delivery": [{"as": "file", "name": "GOOGLE_APPLICATION_CREDENTIALS", "ref": "@GOOGLE_SERVICE_ACCOUNT"}]
    },
    {
      "name": "build.config",
      "root": "apps/server",
      "delivery": [{"as": "xcconfig", "name": "API_BASE_URL", "ref": "@API_BASE_URL", "output": "apps/server/Config/Secrets.generated.xcconfig"}]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(projectRoot, ".hasp.manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"project", "doctor", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("project doctor --json: %v", err)
	}
	body := stdout.String()
	if strings.Contains(body, "hasp-missing-doctor-command") || strings.Contains(body, scriptPath) || strings.Contains(body, "https://api.example.test") {
		t.Fatalf("project doctor exposed unsafe diagnostic detail: %s", body)
	}
	var payload struct {
		Diagnostics []struct {
			Code   string `json:"code"`
			Target string `json:"target"`
			Ref    string `json:"ref"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode project doctor payload: %v\nbody=%s", err, body)
	}
	want := map[string]bool{
		"target_command_unavailable/release.sign/":             false,
		"target_output_unignored/build.config/":                false,
		"secret_workspace_delivery/build.config/@API_BASE_URL": false,
		"requirement_kind_mismatch//@GOOGLE_SERVICE_ACCOUNT":   false,
	}
	for _, diag := range payload.Diagnostics {
		key := diag.Code + "/" + diag.Target + "/" + diag.Ref
		if _, ok := want[key]; ok {
			want[key] = true
		}
		if diag.Code == "target_command_unavailable" && diag.Target == "server.dev" {
			t.Fatalf("relative executable command should not be flagged: %+v", diag)
		}
	}
	for key, found := range want {
		if !found {
			t.Fatalf("missing diagnostic %s in %+v", key, payload.Diagnostics)
		}
	}
}

func TestProjectGeneratedOutputIgnoredRejectsOutsideProject(t *testing.T) {
	if projectGeneratedOutputIgnored(context.Background(), t.TempDir(), filepath.Join(t.TempDir(), "Secrets.generated.xcconfig")) {
		t.Fatal("outside-project output must not be treated as ignored")
	}
}

func setupProjectTargetManifestFixture(t *testing.T) (projectRoot string, secretValue string, sentinel string) {
	t.Helper()
	homeDir := t.TempDir()
	projectRoot = t.TempDir()
	sentinel = filepath.Join(t.TempDir(), "target-command-ran")
	secretValue = "sk-red-fixture-secret"

	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if err := os.MkdirAll(filepath.Join(projectRoot, "apps", "server"), 0o755); err != nil {
		t.Fatalf("mkdir apps/server: %v", err)
	}
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "OPENAI_API_KEY", "--value", secretValue}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set secret: %v", err)
	}

	manifest := fmt.Sprintf(`{
  "version": "v1",
  "project": {"name": "fixture"},
  "references": [{"alias": "secret_01", "item": "OPENAI_API_KEY"}],
  "requirements": [{"ref": "@OPENAI_API_KEY", "kind": "kv", "classification": "secret", "required": true}],
  "targets": [
    {
      "name": "server.dev",
      "root": "apps/server",
      "command": ["sh", "-c", "touch %s"],
      "delivery": [{"as": "env", "name": "OPENAI_API_KEY", "ref": "@OPENAI_API_KEY"}],
      "examples": [{"format": "env", "path": "apps/server/.env.example"}]
    }
  ]
}`, sentinel)
	if err := os.WriteFile(filepath.Join(projectRoot, ".hasp.manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return projectRoot, secretValue, sentinel
}
