package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
)

func TestWriteEnvCheckRepoAndExecutionErrorBranches(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	testStarter := &fakeStarter{}
	origEnsureSession := ensureSessionAppFn
	defer func() { ensureSessionAppFn = origEnsureSession }()
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "test-session"}, nil
	}

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set api_token: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "secret_01=api_token"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run project bind: %v", err)
	}

	if err := writeEnvCommand(context.Background(), []string{"--bad"}, io.Discard, io.Discard, testStarter); err == nil {
		t.Fatal("expected write-env parse error")
	}
	if err := writeEnvCommand(context.Background(), []string{"--project-root", projectRoot, "--output", filepath.Join(projectRoot, ".env"), "--env", "API_TOKEN=secret_01"}, io.Discard, io.Discard, testStarter); err == nil {
		t.Fatal("expected write-env approval error without grants")
	}
	if err := writeEnvCommand(context.Background(), []string{"--project-root", projectRoot, "--output", filepath.Join(projectRoot, ".env"), "--env", "API_TOKEN=secret_01", "--grant-project", "window", "--grant-secret", "session", "--grant-convenience", "window"}, errWriter{err: errors.New("write-env encode failure")}, io.Discard, testStarter); err == nil {
		t.Fatal("expected write-env encode failure")
	}
	var warningErr bytes.Buffer
	var warningOut bytes.Buffer
	insideProjectPath := filepath.Join(projectRoot, ".env.inside")
	if err := writeEnvCommand(context.Background(), []string{"--project-root", projectRoot, "--output", insideProjectPath, "--env", "API_TOKEN=secret_01", "--grant-project", "window", "--grant-secret", "session", "--grant-convenience", "window"}, &warningOut, &warningErr, testStarter); err != nil {
		t.Fatalf("write-env warning case: %v", err)
	}
	if !strings.Contains(warningErr.String(), "destination is inside the bound project") {
		t.Fatalf("expected inside-project warning, got %q", warningErr.String())
	}

	outputDir := filepath.Join(t.TempDir(), "envdir")
	if err := os.Mkdir(outputDir, 0o755); err != nil {
		t.Fatalf("mkdir output dir: %v", err)
	}
	if err := writeEnvCommand(context.Background(), []string{"--project-root", projectRoot, "--output", outputDir, "--env", "API_TOKEN=secret_01", "--grant-project", "window", "--grant-secret", "session"}, io.Discard, io.Discard, testStarter); err == nil {
		t.Fatal("expected write-env open failure")
	}

	appendPath := filepath.Join(t.TempDir(), "env.out")
	if err := os.WriteFile(appendPath, []byte("EXISTING=1\n"), 0o600); err != nil {
		t.Fatalf("write append file: %v", err)
	}
	if err := writeEnvCommand(context.Background(), []string{"--project-root", projectRoot, "--output", appendPath, "--append", "--env", "API_TOKEN=secret_01", "--grant-project", "window", "--grant-secret", "session", "--grant-convenience", "window"}, io.Discard, io.Discard, testStarter); err != nil {
		t.Fatalf("write-env append: %v", err)
	}
	appended, err := os.ReadFile(appendPath)
	if err != nil {
		t.Fatalf("read appended env file: %v", err)
	}
	if !strings.Contains(string(appended), "EXISTING=1") || !strings.Contains(string(appended), "API_TOKEN=abc123") {
		t.Fatalf("unexpected appended env file: %q", string(appended))
	}

	secretPath := filepath.Join(projectRoot, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("abc123"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	var overrideOut bytes.Buffer
	if err := checkRepoCommand(context.Background(), []string{"--json", "--project-root", projectRoot, "--allow-managed-secrets"}, &overrideOut); err != nil {
		t.Fatalf("check repo override: %v", err)
	}
	if !strings.Contains(overrideOut.String(), "\"override\":true") {
		t.Fatalf("expected override response, got %q", overrideOut.String())
	}
	if err := checkRepoCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected check-repo parse error")
	}

	cleanRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(cleanRoot, "README.txt"), []byte("clean"), 0o600); err != nil {
		t.Fatalf("write clean file: %v", err)
	}
	var cleanOut bytes.Buffer
	if err := checkRepoCommand(context.Background(), []string{"--json", "--project-root", cleanRoot}, &cleanOut); err != nil {
		t.Fatalf("check repo clean: %v", err)
	}
	if !strings.Contains(cleanOut.String(), "\"matches\":null") {
		t.Fatalf("expected empty match response, got %q", cleanOut.String())
	}
	brokenRoot := t.TempDir()
	if err := os.Symlink(filepath.Join(brokenRoot, "missing-target"), filepath.Join(brokenRoot, "broken-link")); err != nil {
		t.Fatalf("write broken symlink: %v", err)
	}
	if err := checkRepoCommand(context.Background(), []string{"--project-root", brokenRoot}, io.Discard); err == nil {
		t.Fatal("expected check-repo read failure on broken symlink")
	}

	writeErr := errors.New("stdout write failure")
	if err := executeCommand(context.Background(), []string{"--project-root", projectRoot, "--env", "API_TOKEN=secret_01", "--grant-project", "window", "--grant-secret", "session", "--", "sh", "-c", "printf '%s' \"$API_TOKEN\""}, errWriter{err: writeErr}, io.Discard, false, testStarter); !errors.Is(err, writeErr) {
		t.Fatalf("expected stdout write failure, got %v", err)
	}
	stderrWriteErr := errors.New("stderr write failure")
	if err := executeCommand(context.Background(), []string{"--project-root", projectRoot, "--env", "API_TOKEN=secret_01", "--grant-project", "window", "--grant-secret", "session", "--", "sh", "-c", "printf '%s' \"$API_TOKEN\" >&2"}, io.Discard, errWriter{err: stderrWriteErr}, false, testStarter); !errors.Is(err, stderrWriteErr) {
		t.Fatalf("expected stderr write failure, got %v", err)
	}
	if err := runWithStarter(context.Background(), []string{"run", "--project-root", projectRoot, "--", "sh", "-c", "exit 7"}, bytes.NewBuffer(nil), io.Discard, io.Discard, testStarter); err == nil || !strings.Contains(err.Error(), "command exited with code 7") {
		t.Fatalf("expected exit code error, got %v", err)
	}
	if err := runWithStarter(context.Background(), []string{"run", "--project-root", projectRoot, "--", "/definitely-missing-binary"}, bytes.NewBuffer(nil), io.Discard, io.Discard, testStarter); err == nil {
		t.Fatal("expected runner execution error")
	}
	var daemonHelp bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"daemon"}, bytes.NewBuffer(nil), &daemonHelp, io.Discard, testStarter); err != nil {
		t.Fatalf("expected daemon help, got %v", err)
	}
	if !strings.Contains(daemonHelp.String(), "Manage the local runtime daemon") {
		t.Fatalf("expected daemon help output, got %q", daemonHelp.String())
	}
	if err := runWithStarter(context.Background(), []string{"inject"}, bytes.NewBuffer(nil), io.Discard, io.Discard, testStarter); err == nil {
		t.Fatal("expected inject dispatch usage error")
	}
}

func TestSecretCommandsParseAndWriterBranches(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	envPath := filepath.Join(t.TempDir(), ".env")
	filePath := filepath.Join(t.TempDir(), "secret.bin")
	if err := os.WriteFile(envPath, []byte("API_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	if err := os.WriteFile(filePath, []byte("file-secret"), 0o600); err != nil {
		t.Fatalf("write file secret: %v", err)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	testStarter := &fakeStarter{}
	origEnsureSession := ensureSessionAppFn
	defer func() { ensureSessionAppFn = origEnsureSession }()
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "test-session"}, nil
	}

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := initCommand(context.Background(), io.Discard); err == nil {
		t.Fatal("expected second init failure")
	}
	if err := initCommand(context.Background(), errWriter{err: errors.New("init writer failure")}); err == nil {
		t.Fatal("expected init writer failure")
	}
	if err := projectBindCommand(context.Background(), []string{"--project-root", projectRoot, "--hooks=false"}, io.Discard); err != nil {
		t.Fatalf("project bind: %v", err)
	}

	if err := importCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected import parse error")
	}
	txtPath := filepath.Join(t.TempDir(), "secrets.txt")
	if err := os.WriteFile(txtPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write txt file: %v", err)
	}
	if err := importCommand(context.Background(), []string{txtPath}, io.Discard); err == nil {
		t.Fatal("expected import unsupported-format failure")
	}
	importErr := errors.New("import writer failure")
	if err := importCommand(context.Background(), []string{"--name", "imported", envPath}, errWriter{err: importErr}); !errors.Is(err, importErr) {
		t.Fatalf("expected import writer failure, got %v", err)
	}
	if err := importCommand(context.Background(), []string{filepath.Join(t.TempDir(), "missing.env")}, io.Discard); err == nil {
		t.Fatal("expected import missing-file failure")
	}
	if err := setCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected set parse error")
	}
	setErr := errors.New("set writer failure")
	if err := setCommand(context.Background(), []string{"--name", "file_secret", "--kind", "file", "--from-file", filePath}, errWriter{err: setErr}); !errors.Is(err, setErr) {
		t.Fatalf("expected set writer failure, got %v", err)
	}
	if err := setCommand(context.Background(), []string{"--name", "bad_kind", "--kind", "bogus", "--value", "x"}, io.Discard); err == nil {
		t.Fatal("expected set unsupported-kind failure")
	}
	if err := setCommand(context.Background(), []string{"--name", "missing_file_secret", "--from-file", filepath.Join(t.TempDir(), "missing.bin")}, io.Discard); err == nil {
		t.Fatal("expected set missing-file failure")
	}
	if err := captureCommand(context.Background(), []string{"--bad"}, io.Discard, testStarter); err == nil {
		t.Fatal("expected capture parse error")
	}
	captureErr := errors.New("capture writer failure")
	if err := captureCommand(context.Background(), []string{"--name", "captured_secret", "--value", "top-secret", "--project-root", projectRoot, "--grant-project", "window", "--grant-write"}, errWriter{err: captureErr}, testStarter); !errors.Is(err, captureErr) {
		t.Fatalf("expected capture writer failure, got %v", err)
	}
	if err := captureCommand(context.Background(), []string{"--name", "broken_capture", "--from-file", filepath.Join(t.TempDir(), "missing.txt"), "--project-root", projectRoot, "--grant-project", "window", "--grant-write"}, io.Discard, testStarter); err == nil {
		t.Fatal("expected capture missing-file failure")
	}
	if err := captureCommand(context.Background(), []string{"--name", "capture_bad_kind", "--kind", "bogus", "--value", "x", "--project-root", projectRoot, "--grant-project", "window", "--grant-write"}, io.Discard, testStarter); err == nil {
		t.Fatal("expected capture unsupported-kind failure")
	}
	if err := captureCommand(context.Background(), []string{"--name", "captured_secret", "--value", "updated-secret", "--project-root", projectRoot, "--grant-project", "window", "--grant-secret", "session"}, io.Discard, testStarter); err != nil {
		t.Fatalf("capture update existing item: %v", err)
	}
	redactErr := errors.New("redact writer failure")
	if err := redactCommand(context.Background(), bytes.NewBufferString("captured_secret=updated-secret"), errWriter{err: redactErr}); !errors.Is(err, redactErr) {
		t.Fatalf("expected redact writer failure, got %v", err)
	}
	t.Setenv("HASP_MASTER_PASSWORD", "wrong password")
	if err := importCommand(context.Background(), []string{envPath}, io.Discard); err == nil {
		t.Fatal("expected import wrong-password failure")
	}
	if err := setCommand(context.Background(), []string{"--name", "wrong_password_secret", "--value", "x"}, io.Discard); err == nil {
		t.Fatal("expected set wrong-password failure")
	}
	if err := captureCommand(context.Background(), []string{"--name", "wrong_password_capture", "--value", "x", "--project-root", projectRoot, "--grant-project", "window", "--grant-write"}, io.Discard, testStarter); err == nil {
		t.Fatal("expected capture wrong-password failure")
	}
	if err := redactCommand(context.Background(), bytes.NewBufferString("secret"), io.Discard); err == nil {
		t.Fatal("expected redact wrong-password failure")
	}
}
