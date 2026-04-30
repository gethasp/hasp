package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunTargetInjectsOnlyDeclaredEnvAndRejectsAdditiveMappings(t *testing.T) {
	projectRoot, starter := setupTargetRuntimeFixture(t)
	targetRoot := canonicalPathForTest(t, filepath.Join(projectRoot, "apps", "web"))

	var stdout, stderr bytes.Buffer
	err := runWithStarter(context.Background(), []string{
		"run",
		"--project-root", projectRoot,
		"--target", "web.dev",
		"--grant-project", "window",
		"--grant-secret", "session",
		"--grant-window", "15m",
		"--",
		"sh", "-c", `got="$(pwd -P)"; test "$got" = "$1" || { echo "cwd=$got want=$1" >&2; exit 1; }; test -n "$OPENAI_API_KEY" || { echo "missing OPENAI_API_KEY" >&2; exit 1; }; test -z "$DATABASE_URL" || { echo "unexpected DATABASE_URL" >&2; exit 1; }`, "target-root-check", targetRoot,
	}, bytes.NewBuffer(nil), &stdout, &stderr, starter)
	if err != nil {
		t.Fatalf("run --target: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "sk-web-value") || strings.Contains(stderr.String(), "sk-web-value") {
		t.Fatalf("target run exposed a secret value\nstdout=%s\nstderr=%s", stdout.String(), stderr.String())
	}

	err = runWithStarter(context.Background(), []string{
		"run",
		"--project-root", projectRoot,
		"--target", "web.dev",
		"--env", "DATABASE_URL=@DATABASE_URL",
		"--",
		"true",
	}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter)
	if err == nil || !strings.Contains(err.Error(), "--target cannot be combined") {
		t.Fatalf("expected additive mapping refusal, got %v", err)
	}
}

func TestAppConnectTargetSeedsLocalProfileIndependently(t *testing.T) {
	lockAppSeams(t)
	projectRoot, starter := setupTargetRuntimeFixture(t)

	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), []string{
		"app", "connect", "web",
		"--project-root", projectRoot,
		"--target", "web.dev",
	}, bytes.NewBuffer(nil), &stdout, &stderr); err != nil {
		t.Fatalf("app connect --target: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	consumer, err := handle.GetAppConsumer("web")
	if err != nil {
		t.Fatalf("get app consumer: %v", err)
	}
	if consumer.ProjectRoot != canonicalPathForTest(t, projectRoot) {
		t.Fatalf("expected app profile to stay bound to project root %q, got %q", projectRoot, consumer.ProjectRoot)
	}
	command := strings.Join(consumer.Command, " ")
	if !strings.Contains(command, "test -n") || strings.Contains(command, "sk-web-value") {
		t.Fatalf("unexpected seeded command %q", command)
	}
	if len(consumer.Bindings) != 1 || consumer.Bindings[0].Target != "OPENAI_API_KEY" || consumer.Bindings[0].SecretName != "OPENAI_API_KEY" {
		t.Fatalf("unexpected seeded bindings %+v", consumer.Bindings)
	}

	if err := Run(context.Background(), []string{
		"app", "connect", "deployapp",
		"--project-root", projectRoot,
		"--target", "deploy.production",
	}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "has no command") {
		t.Fatalf("expected commandless target refusal, got %v", err)
	}
	if err := Run(context.Background(), []string{
		"app", "connect", "deployapp",
		"--project-root", projectRoot,
		"--target", "deploy.production",
		"--cmd", `test -s "$GOOGLE_APPLICATION_CREDENTIALS"`,
	}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("app connect commandless target with override: %v", err)
	}
	if err := Run(context.Background(), []string{
		"app", "connect", "macapp",
		"--project-root", projectRoot,
		"--target", "macos.debug",
	}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "workspace-visible delivery") {
		t.Fatalf("expected xcconfig target refusal for app connect, got %v", err)
	}

	rewriteWebTargetManifest(t, projectRoot)
	var runOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"app", "run", "web"}, bytes.NewBuffer(nil), &runOut, &stderr, starter); err != nil {
		t.Fatalf("app run should use the local profile seeded before manifest drift: %v\nstdout=%s\nstderr=%s", err, runOut.String(), stderr.String())
	}
	if strings.Contains(runOut.String(), "sk-web-value") {
		t.Fatalf("app run exposed a target secret value: %s", runOut.String())
	}
}

func TestTargetRuntimeAndDoctorSurfaceManifestDrift(t *testing.T) {
	projectRoot, starter := setupTargetRuntimeFixture(t)

	if err := runWithStarter(context.Background(), []string{
		"run",
		"--project-root", projectRoot,
		"--target", "web.dev",
		"--grant-project", "window",
		"--grant-secret", "session",
		"--grant-window", "15m",
		"--",
		"true",
	}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter); err != nil {
		t.Fatalf("initial run --target: %v", err)
	}

	rewriteWebTargetManifest(t, projectRoot)
	var doctorOut bytes.Buffer
	if err := Run(context.Background(), []string{"project", "doctor", "--json", "--project-root", projectRoot}, bytes.NewBuffer(nil), &doctorOut, io.Discard); err != nil {
		t.Fatalf("project doctor after target drift: %v", err)
	}
	var doctorPayload struct {
		Diagnostics []struct {
			Code   string `json:"code"`
			Target string `json:"target"`
			Stale  bool   `json:"stale"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(doctorOut.Bytes(), &doctorPayload); err != nil {
		t.Fatalf("decode project doctor payload: %v\nbody=%s", err, doctorOut.String())
	}
	found := false
	for _, diag := range doctorPayload.Diagnostics {
		if diag.Code == "target_drift" && diag.Target == "web.dev" && diag.Stale {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected target_drift diagnostic, got %+v", doctorPayload.Diagnostics)
	}

	var stderr bytes.Buffer
	if err := runWithStarter(context.Background(), []string{
		"run",
		"--project-root", projectRoot,
		"--target", "web.dev",
		"--grant-project", "window",
		"--grant-secret", "session",
		"--grant-window", "15m",
		"--",
		"true",
	}, bytes.NewBuffer(nil), io.Discard, &stderr, starter); err != nil {
		t.Fatalf("second run --target after drift: %v\nstderr=%s", err, stderr.String())
	}
	warning := stderr.String()
	for _, want := range []string{"manifest target \"web.dev\" changed", "command", "refs", "delivery"} {
		if !strings.Contains(warning, want) {
			t.Fatalf("expected drift warning to contain %q, got %q", want, warning)
		}
	}
}

func TestInjectTargetProvidesDeclaredTempFileOnly(t *testing.T) {
	projectRoot, starter := setupTargetRuntimeFixture(t)

	var stdout, stderr bytes.Buffer
	err := runWithStarter(context.Background(), []string{
		"inject",
		"--project-root", projectRoot,
		"--target", "deploy.production",
		"--grant-project", "window",
		"--grant-secret", "session",
		"--grant-window", "15m",
		"--",
		"sh", "-c", `test -s "$GOOGLE_APPLICATION_CREDENTIALS" && test -z "$OPENAI_API_KEY"`,
	}, bytes.NewBuffer(nil), &stdout, &stderr, starter)
	if err != nil {
		t.Fatalf("inject --target: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "fixture-service-account") || strings.Contains(stderr.String(), "fixture-service-account") {
		t.Fatalf("target inject exposed a file secret value\nstdout=%s\nstderr=%s", stdout.String(), stderr.String())
	}
}

func TestWriteEnvTargetUsesConfiguredOutputAndRequiresConvenienceGrant(t *testing.T) {
	projectRoot, starter := setupTargetRuntimeFixture(t)
	output := filepath.Join(projectRoot, "apps", "macos", "Config", "Secrets.generated.xcconfig")

	err := runWithStarter(context.Background(), []string{
		"write-env",
		"--project-root", projectRoot,
		"--target", "macos.debug",
		"--grant-project", "window",
		"--grant-secret", "session",
		"--grant-window", "15m",
	}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter)
	if err == nil || !strings.Contains(err.Error(), "convenience approval required") {
		t.Fatalf("expected convenience approval requirement, got %v", err)
	}

	if err := runWithStarter(context.Background(), []string{
		"write-env",
		"--project-root", projectRoot,
		"--target", "macos.debug",
		"--grant-project", "window",
		"--grant-secret", "session",
		"--grant-convenience", "window",
		"--grant-window", "15m",
	}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter); err != nil {
		t.Fatalf("write-env --target: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read target output: %v", err)
	}
	if got := string(data); !strings.Contains(got, "API_BASE_URL = https://api.example.test") {
		t.Fatalf("unexpected xcconfig output %q", got)
	}
}

func setupTargetRuntimeFixture(t *testing.T) (projectRoot string, starter starter) {
	t.Helper()

	homeDir := t.TempDir()
	projectRoot = t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if err := os.MkdirAll(filepath.Join(projectRoot, "apps", "web"), 0o755); err != nil {
		t.Fatalf("mkdir web target root: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(projectRoot, "apps", "macos", "Config"), 0o755); err != nil {
		t.Fatalf("mkdir macos target root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, ".gitignore"), []byte("apps/macos/Config/Secrets.generated.xcconfig\n"), 0o600); err != nil {
		t.Fatalf("write gitignore: %v", err)
	}
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	for _, tc := range []struct {
		name  string
		kind  string
		value string
	}{
		{name: "OPENAI_API_KEY", kind: "kv", value: "sk-web-value"},
		{name: "DATABASE_URL", kind: "kv", value: "postgres://unused"},
		{name: "API_BASE_URL", kind: "kv", value: "https://api.example.test"},
		{name: "GOOGLE_SERVICE_ACCOUNT", kind: "file", value: `{"client_email":"fixture-service-account"}`},
	} {
		args := []string{"secret", "add", "--kind", tc.kind, "--from-stdin", "--vault-only", tc.name}
		if err := Run(context.Background(), args, bytes.NewBufferString(tc.value), io.Discard, io.Discard); err != nil {
			t.Fatalf("secret add %s: %v", tc.name, err)
		}
	}
	manifest := `{
  "version": "v1",
  "references": [
    {"alias": "secret_01", "item": "OPENAI_API_KEY"},
    {"alias": "secret_02", "item": "DATABASE_URL"},
    {"alias": "config_01", "item": "API_BASE_URL"},
    {"alias": "file_01", "item": "GOOGLE_SERVICE_ACCOUNT"}
  ],
  "requirements": [
    {"ref": "@OPENAI_API_KEY", "kind": "kv", "classification": "secret", "required": true},
    {"ref": "@DATABASE_URL", "kind": "kv", "classification": "secret", "required": true},
    {"ref": "@API_BASE_URL", "kind": "kv", "classification": "public_config", "required": true},
    {"ref": "@GOOGLE_SERVICE_ACCOUNT", "kind": "file", "classification": "secret", "required": true}
  ],
  "targets": [
    {
      "name": "web.dev",
      "root": "apps/web",
      "command": ["sh", "-c", "test -n \"$OPENAI_API_KEY\""],
      "delivery": [{"as": "env", "name": "OPENAI_API_KEY", "ref": "@OPENAI_API_KEY"}]
    },
    {
      "name": "deploy.production",
      "root": ".",
      "delivery": [{"as": "file", "name": "GOOGLE_APPLICATION_CREDENTIALS", "ref": "@GOOGLE_SERVICE_ACCOUNT"}]
    },
    {
      "name": "macos.debug",
      "root": "apps/macos",
      "delivery": [{"as": "xcconfig", "name": "API_BASE_URL", "ref": "@API_BASE_URL", "output": "apps/macos/Config/Secrets.generated.xcconfig"}]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(projectRoot, ".hasp.manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := Run(context.Background(), []string{
		"project", "bind",
		"--project-root", projectRoot,
		"--alias", "secret_01=OPENAI_API_KEY",
		"--alias", "secret_02=DATABASE_URL",
		"--alias", "config_01=API_BASE_URL",
		"--alias", "file_01=GOOGLE_SERVICE_ACCOUNT",
	}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("project bind: %v", err)
	}
	return projectRoot, newDaemonTestStarter(t)
}

func rewriteWebTargetManifest(t *testing.T, projectRoot string) {
	t.Helper()
	manifest := `{
  "version": "v1",
  "references": [
    {"alias": "secret_01", "item": "OPENAI_API_KEY"},
    {"alias": "secret_02", "item": "DATABASE_URL"},
    {"alias": "config_01", "item": "API_BASE_URL"},
    {"alias": "file_01", "item": "GOOGLE_SERVICE_ACCOUNT"}
  ],
  "requirements": [
    {"ref": "@OPENAI_API_KEY", "kind": "kv", "classification": "secret", "required": true},
    {"ref": "@DATABASE_URL", "kind": "kv", "classification": "secret", "required": true},
    {"ref": "@API_BASE_URL", "kind": "kv", "classification": "public_config", "required": true},
    {"ref": "@GOOGLE_SERVICE_ACCOUNT", "kind": "file", "classification": "secret", "required": true}
  ],
  "targets": [
    {
      "name": "web.dev",
      "root": "apps/web",
      "command": ["sh", "-c", "false"],
      "delivery": [{"as": "env", "name": "DATABASE_URL", "ref": "@DATABASE_URL"}]
    },
    {
      "name": "deploy.production",
      "root": ".",
      "delivery": [{"as": "file", "name": "GOOGLE_APPLICATION_CREDENTIALS", "ref": "@GOOGLE_SERVICE_ACCOUNT"}]
    },
    {
      "name": "macos.debug",
      "root": "apps/macos",
      "delivery": [{"as": "xcconfig", "name": "API_BASE_URL", "ref": "@API_BASE_URL", "output": "apps/macos/Config/Secrets.generated.xcconfig"}]
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(projectRoot, ".hasp.manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatalf("rewrite manifest: %v", err)
	}
}

func canonicalPathForTest(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("abs path %q: %v", path, err)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}
