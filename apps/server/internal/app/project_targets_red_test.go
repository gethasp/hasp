package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
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

func TestProjectManifestMissingReturnsActionableError(t *testing.T) {
	lockAppSeams(t)
	projectRoot := t.TempDir()

	err := Run(context.Background(), []string{"project", "targets", "--project-root", projectRoot}, bytes.NewBuffer(nil), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected missing manifest error")
	}
	var envelope *appError
	if !errors.As(err, &envelope) {
		t.Fatalf("expected appError, got %T %v", err, err)
	}
	if envelope.Code != errCodeNotFound || !strings.Contains(envelope.Hint, "hasp project init") {
		t.Fatalf("unexpected missing manifest error: %+v", envelope)
	}
}

func TestProjectTargetAddCreatesValueFreeManifest(t *testing.T) {
	lockAppSeams(t)
	projectRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectRoot, "apps", "gum"), 0o755); err != nil {
		t.Fatalf("mkdir apps/gum: %v", err)
	}

	var stdout bytes.Buffer
	err := Run(context.Background(), []string{
		"project", "target", "add", "release.build",
		"--project-root", projectRoot,
		"--root", "apps/gum",
		"--env", "GUM_OAUTH_CLIENT_SECRET=@GUM_OAUTH_CLIENT_SECRET",
		"--env-example", "apps/gum/.env.example",
		"--json",
		"--", "goreleaser", "release",
	}, bytes.NewBuffer(nil), &stdout, io.Discard)
	if err != nil {
		t.Fatalf("project target add: %v", err)
	}
	body := stdout.String()
	if strings.Contains(body, "goreleaser") {
		t.Fatalf("target add JSON should not echo repo-controlled command argv: %s", body)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(projectRoot, ".hasp.manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if strings.Contains(string(manifestBytes), "client-secret-value") {
		t.Fatalf("manifest stored a raw value: %s", string(manifestBytes))
	}
	manifest, err := store.DecodeRepoManifest(projectRoot, manifestBytes)
	if err != nil {
		t.Fatalf("decode generated manifest: %v\n%s", err, manifestBytes)
	}
	target, ok := manifest.Target("release.build")
	if !ok {
		t.Fatalf("generated manifest missing target: %+v", manifest)
	}
	if target.Root != "apps/gum" || !slices.Equal(target.Command, []string{"goreleaser", "release"}) {
		t.Fatalf("unexpected target: %+v", target)
	}
	if len(target.Delivery) != 1 || target.Delivery[0].Name != "GUM_OAUTH_CLIENT_SECRET" || target.Delivery[0].Ref != "@GUM_OAUTH_CLIENT_SECRET" {
		t.Fatalf("unexpected delivery: %+v", target.Delivery)
	}
	if _, ok := manifest.Requirement("@GUM_OAUTH_CLIENT_SECRET"); !ok {
		t.Fatalf("generated manifest missing requirement: %+v", manifest.Requirements)
	}
	if item, ok := manifest.ItemNameForRef("@GUM_OAUTH_CLIENT_SECRET"); !ok || item != "GUM_OAUTH_CLIENT_SECRET" {
		t.Fatalf("generated manifest missing reference, got %q ok=%v", item, ok)
	}
}

func TestTemplateAddAliasCreatesValueFreeManifest(t *testing.T) {
	lockAppSeams(t)
	projectRoot := t.TempDir()

	if err := Run(context.Background(), []string{
		"template", "add", "server.dev",
		"--project-root", projectRoot,
		"--env", "OPENAI_API_KEY=@OPENAI_API_KEY",
		"--", "npm", "test",
	}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("template add: %v", err)
	}
	if _, err := store.LoadRepoManifest(projectRoot); err != nil {
		t.Fatalf("template add did not create a valid manifest: %v", err)
	}
}

func TestProjectTargetAddRejectsNonNamedRefs(t *testing.T) {
	lockAppSeams(t)
	projectRoot := t.TempDir()

	err := Run(context.Background(), []string{
		"project", "target", "add", "server.dev",
		"--project-root", projectRoot,
		"--env", "OPENAI_API_KEY=literal-value",
	}, bytes.NewBuffer(nil), io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "named refs") {
		t.Fatalf("expected named-ref rejection, got %v", err)
	}
}

func TestProjectTargetReviewRecordsSignatureWithoutExecutingTarget(t *testing.T) {
	lockAppSeams(t)
	projectRoot, secretValue, sentinel := setupProjectTargetManifestFixture(t)

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{
		"project", "target", "review", "server.dev",
		"--project-root", projectRoot,
		"--json",
	}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("project target review: %v", err)
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatalf("project target review executed target command and created %s", sentinel)
	}
	body := stdout.String()
	for _, forbidden := range []string{secretValue, "touch " + sentinel} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("project target review exposed forbidden content %q in %s", forbidden, body)
		}
	}
	manifest, err := store.ExpandManifestTarget(projectRoot, "server.dev")
	if err != nil {
		t.Fatalf("expand target: %v", err)
	}
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	drift, err := handle.ManifestTargetDrift(projectRoot, manifest)
	if err != nil {
		t.Fatalf("target drift: %v", err)
	}
	if !drift.Known || drift.Changed {
		t.Fatalf("expected reviewed unchanged target, got %+v", drift)
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

func TestProjectSurfacesCredentialSetTargets(t *testing.T) {
	lockAppSeams(t)
	projectRoot := setupProjectCredentialSetManifestFixture(t)

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"project", "targets", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("project targets --json: %v", err)
	}
	var targetsPayload struct {
		Targets []struct {
			Name           string   `json:"name"`
			Refs           []string `json:"refs"`
			CredentialSets []string `json:"credential_sets"`
			HasEnv         bool     `json:"has_env"`
			HasXCConfig    bool     `json:"has_xcconfig"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &targetsPayload); err != nil {
		t.Fatalf("decode targets payload: %v\nbody=%s", err, stdout.String())
	}
	targetsByName := map[string]struct {
		Refs           []string
		CredentialSets []string
		HasEnv         bool
		HasXCConfig    bool
	}{}
	for _, target := range targetsPayload.Targets {
		targetsByName[target.Name] = struct {
			Refs           []string
			CredentialSets []string
			HasEnv         bool
			HasXCConfig    bool
		}{target.Refs, target.CredentialSets, target.HasEnv, target.HasXCConfig}
	}
	if got := targetsByName["server.dev"]; !got.HasEnv || !slices.Equal(got.Refs, []string{"config_01", "secret_01"}) || !slices.Equal(got.CredentialSets, []string{"google.oauth.web"}) {
		t.Fatalf("server.dev target view = %+v", got)
	}
	if got := targetsByName["ios.config"]; !got.HasXCConfig || !slices.Equal(got.Refs, []string{"secret_01"}) || !slices.Equal(got.CredentialSets, []string{"google.oauth.web"}) {
		t.Fatalf("ios.config target view = %+v", got)
	}

	stdout.Reset()
	if err := Run(context.Background(), []string{"project", "requirements", "--json", "--project-root", projectRoot, "--target", "server.dev"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("project requirements --json --target: %v", err)
	}
	var requirementsPayload struct {
		Requirements []struct {
			Ref     string   `json:"ref"`
			Targets []string `json:"targets"`
		} `json:"requirements"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &requirementsPayload); err != nil {
		t.Fatalf("decode requirements payload: %v\nbody=%s", err, stdout.String())
	}
	refsByTarget := map[string][]string{}
	for _, req := range requirementsPayload.Requirements {
		refsByTarget[req.Ref] = req.Targets
	}
	if len(refsByTarget) != 2 || !slices.Equal(refsByTarget["config_01"], []string{"server.dev"}) || !slices.Equal(refsByTarget["secret_01"], []string{"server.dev"}) {
		t.Fatalf("requirements target filter did not resolve set roles: %+v", refsByTarget)
	}

	if err := Run(context.Background(), []string{"project", "examples", "--write", "--project-root", projectRoot, "--target", "server.dev"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("project examples --write: %v", err)
	}
	example, err := os.ReadFile(filepath.Join(projectRoot, "apps", "server", ".env.example"))
	if err != nil {
		t.Fatalf("read generated example: %v", err)
	}
	exampleBody := string(example)
	for _, want := range []string{
		`GOOGLE_CLIENT_ID="__HASP_PUBLIC_CONFIG__"`,
		`GOOGLE_CLIENT_SECRET="__HASP_SECRET__"`,
	} {
		if !strings.Contains(exampleBody, want) {
			t.Fatalf("generated example missing %q in %s", want, exampleBody)
		}
	}

	stdout.Reset()
	if err := Run(context.Background(), []string{"project", "doctor", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("project doctor --json: %v", err)
	}
	var doctorPayload struct {
		Diagnostics []struct {
			Code   string `json:"code"`
			Target string `json:"target"`
			Ref    string `json:"ref"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doctorPayload); err != nil {
		t.Fatalf("decode doctor payload: %v\nbody=%s", err, stdout.String())
	}
	foundSecretWorkspaceDelivery := false
	for _, diag := range doctorPayload.Diagnostics {
		if diag.Code == "secret_workspace_delivery" && diag.Target == "ios.config" && diag.Ref == "secret_01" {
			foundSecretWorkspaceDelivery = true
		}
	}
	if !foundSecretWorkspaceDelivery {
		t.Fatalf("doctor did not resolve set-backed xcconfig secret delivery: %+v", doctorPayload.Diagnostics)
	}
}

func TestProjectHelpersHandleUnresolvedCredentialSetRoles(t *testing.T) {
	manifest := store.RepoManifest{}
	target := store.ManifestTarget{
		Name: "broken",
		Delivery: []store.ManifestDelivery{
			{As: store.ManifestDeliveryEnv, Name: "GOOGLE_CLIENT_SECRET", FromSet: "missing", Role: "client_secret"},
		},
	}
	if _, err := renderProjectExample(manifest, target, store.ManifestExample{Format: store.ManifestExampleEnv}); err == nil {
		t.Fatal("expected unresolved env credential role error")
	}
	target.Delivery[0].As = store.ManifestDeliveryXCConfig
	if _, err := renderProjectExample(manifest, target, store.ManifestExample{Format: store.ManifestExampleXCConfig}); err == nil {
		t.Fatal("expected unresolved xcconfig credential role error")
	}
	diagnostics := buildProjectDoctorDiagnostics(context.Background(), t.TempDir(), store.RepoManifest{Targets: []store.ManifestTarget{target}})
	if len(diagnostics) == 0 || diagnostics[0].Code != "vault_unavailable" {
		t.Fatalf("unexpected diagnostics for unresolved role: %+v", diagnostics)
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

func setupProjectCredentialSetManifestFixture(t *testing.T) string {
	t.Helper()
	projectRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectRoot, "apps", "server"), 0o755); err != nil {
		t.Fatalf("mkdir apps/server: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(projectRoot, "apps", "ios", "Config"), 0o755); err != nil {
		t.Fatalf("mkdir apps/ios/Config: %v", err)
	}
	manifest := `{
  "version": "v1",
  "references": [
    {"alias": "config_01", "item": "GOOGLE_CLIENT_ID"},
    {"alias": "secret_01", "item": "GOOGLE_CLIENT_SECRET"}
  ],
  "requirements": [
    {"ref": "config_01", "kind": "kv", "classification": "public_config", "required": true},
    {"ref": "secret_01", "kind": "kv", "classification": "secret", "required": true}
  ],
  "credential_sets": [
    {
      "name": "google.oauth.web",
      "kind": "google_oauth_client",
      "members": {
        "client_id": "config_01",
        "client_secret": "secret_01"
      }
    }
  ],
  "targets": [
    {
      "name": "server.dev",
      "root": "apps/server",
      "delivery": [
        {"as": "env", "name": "GOOGLE_CLIENT_ID", "from_set": "google.oauth.web", "role": "client_id"},
        {"as": "env", "name": "GOOGLE_CLIENT_SECRET", "from_set": "GOOGLE.OAUTH.WEB", "role": "client_secret"}
      ],
      "examples": [{"format": "env", "path": "apps/server/.env.example"}]
    },
    {
      "name": "ios.config",
      "root": "apps/ios",
      "delivery": [{"as": "xcconfig", "name": "GOOGLE_CLIENT_SECRET", "from_set": "google.oauth.web", "role": "client_secret", "output": "apps/ios/Config/Secrets.generated.xcconfig"}]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(projectRoot, ".hasp.manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatalf("write credential set manifest: %v", err)
	}
	return projectRoot
}
