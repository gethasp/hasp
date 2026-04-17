//go:build integration

package evals

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func TestCLIEndToEndMatrix(t *testing.T) {
	env := newEvalEnv(t)

	writeFilePath := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(writeFilePath, []byte("certificate-data"), 0o600); err != nil {
		t.Fatalf("write file secret: %v", err)
	}
	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("API_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write env import file: %v", err)
	}

	stdout, _, err := runHasp(t, env, "", "version")
	if err != nil || strings.TrimSpace(stdout) == "" {
		t.Fatalf("version failed: %v stdout=%q", err, stdout)
	}
	if _, _, err := runHasp(t, env, "", "init"); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	if _, _, err := runHasp(t, env, "", "import", envFile); err != nil {
		t.Fatalf("import failed: %v", err)
	}
	if _, _, err := runHasp(t, env, "", "set", "--name", "db_url", "--value", "postgres://localhost"); err != nil {
		t.Fatalf("set db_url failed: %v", err)
	}
	if _, _, err := runHasp(t, env, "", "set", "--name", "cert_file", "--kind", "file", "--from-file", writeFilePath); err != nil {
		t.Fatalf("set cert_file failed: %v", err)
	}
	if _, _, err := runHasp(t, env, "", "project", "bind", "--project-root", env.projectRoot, "--alias", "secret_01=API_TOKEN", "--alias", "secret_02=db_url", "--alias", "file_01=cert_file"); err != nil {
		t.Fatalf("project bind failed: %v", err)
	}
	statusOut, _, err := runHasp(t, env, "", "project", "status", "--project-root", env.projectRoot)
	if err != nil {
		t.Fatalf("project status failed: %v", err)
	}
	if !strings.Contains(statusOut, "secret_01") || !strings.Contains(statusOut, "file_01") {
		t.Fatalf("project status missing aliases: %s", statusOut)
	}

	sessionOut, _, err := runHasp(t, env, "", "session", "open", "--host-label", "integration-cli", "--project-root", env.projectRoot)
	if err != nil {
		t.Fatalf("session open failed: %v", err)
	}
	if !strings.Contains(sessionOut, "session_id") {
		t.Fatalf("session open missing session_id: %s", sessionOut)
	}

	runOut, _, err := runHasp(t, env, "", "run", "--project-root", env.projectRoot, "--env", "API_TOKEN=secret_01", "--grant-project", "window", "--grant-secret", "session", "--", "sh", "-c", "printf '%s' \"$API_TOKEN\"")
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if strings.Contains(runOut, "abc123") {
		t.Fatalf("run leaked managed value: %s", runOut)
	}

	injectOut, _, err := runHasp(t, env, "", "inject", "--project-root", env.projectRoot, "--file", "CERT_PATH=file_01", "--grant-project", "window", "--grant-secret", "session", "--", "sh", "-c", "cat \"$CERT_PATH\"")
	if err != nil {
		t.Fatalf("inject failed: %v", err)
	}
	if strings.Contains(injectOut, "certificate-data") {
		t.Fatalf("inject leaked managed file content: %s", injectOut)
	}

	if _, _, err := runHasp(t, env, "", "capture", "--name", "generated_token", "--value", "xyz789", "--project-root", env.projectRoot, "--grant-project", "window"); err == nil {
		t.Fatal("capture without grant_write unexpectedly succeeded")
	}
	captureOut, _, err := runHasp(t, env, "", "capture", "--name", "generated_token", "--value", "xyz789", "--project-root", env.projectRoot, "--grant-project", "window", "--grant-write", "--bind")
	if err != nil {
		t.Fatalf("capture with grant_write failed: %v", err)
	}
	if !strings.Contains(captureOut, "generated_token") {
		t.Fatalf("capture output missing item name: %s", captureOut)
	}

	redactOut, _, err := runHasp(t, env, "token=abc123", "redact")
	if err != nil {
		t.Fatalf("redact failed: %v", err)
	}
	if strings.Contains(redactOut, "abc123") {
		t.Fatalf("redact failed to censor value: %s", redactOut)
	}

	envOutput := filepath.Join(env.projectRoot, ".env.local")
	writeEnvOut, stderr, err := runHasp(t, env, "", "write-env", "--project-root", env.projectRoot, "--output", envOutput, "--env", "API_TOKEN=secret_01", "--env", "DATABASE_URL=secret_02", "--grant-project", "window", "--grant-secret", "session", "--grant-convenience", "window")
	if err != nil {
		t.Fatalf("write-env failed: %v", err)
	}
	if !strings.Contains(stderr, "outside the agent-safe guarantee") && !strings.Contains(writeEnvOut, "outside the agent-safe guarantee") {
		t.Fatalf("write-env missing inside-project warning: stdout=%s stderr=%s", writeEnvOut, stderr)
	}
	envBytes, err := os.ReadFile(envOutput)
	if err != nil {
		t.Fatalf("read env output: %v", err)
	}
	if !strings.Contains(string(envBytes), "API_TOKEN=abc123") || !strings.Contains(string(envBytes), "DATABASE_URL=postgres://localhost") {
		t.Fatalf("write-env output missing entries: %s", string(envBytes))
	}

	if _, _, err := runHasp(t, env, "", "check-repo", "--project-root", env.projectRoot); err == nil {
		t.Fatal("check-repo unexpectedly passed with managed secret materialization")
	}
	if _, _, err := runHasp(t, env, "", "check-repo", "--project-root", env.projectRoot, "--allow-managed-secrets"); err != nil {
		t.Fatalf("check-repo override failed: %v", err)
	}

	backupPath := filepath.Join(t.TempDir(), "hasp.backup.json")
	if _, _, err := runHasp(t, env, "", "export-backup", "--output", backupPath); err != nil {
		t.Fatalf("export-backup failed: %v", err)
	}
	restoreHome := t.TempDir()
	restoreSocket := filepath.Join("/tmp", fmt.Sprintf("hasp-restore-%d.sock", time.Now().UnixNano()))
	restoreEnv := env
	restoreEnv.home = restoreHome
	restoreEnv.socket = restoreSocket
	restoreEnv.masterPassword = "restored-master-password"
	if _, _, err := runHasp(t, restoreEnv, "", "restore-backup", "--input", backupPath); err != nil {
		t.Fatalf("restore-backup failed: %v", err)
	}
	if _, _, err := runHasp(t, restoreEnv, "", "audit"); err != nil {
		t.Fatalf("audit after restore failed: %v", err)
	}

	tuiOut, _, err := runHasp(t, env, "", "tui", "--project-root", env.projectRoot)
	if err != nil {
		t.Fatalf("tui failed: %v", err)
	}
	if !strings.Contains(tuiOut, "HASP TUI") {
		t.Fatalf("unexpected tui output: %s", tuiOut)
	}
	if _, _, err := runHasp(t, env, "", "audit"); err != nil {
		t.Fatalf("audit verify failed: %v", err)
	}

	if _, _, err := runHasp(t, env, "", "project", "unbind", "--project-root", env.projectRoot); err != nil {
		t.Fatalf("project unbind failed: %v", err)
	}
	statusAfterUnbind, _, err := runHasp(t, env, "", "project", "status", "--project-root", env.projectRoot)
	if err != nil {
		t.Fatalf("project status after unbind failed: %v", err)
	}
	if strings.Contains(statusAfterUnbind, "secret_01") {
		t.Fatalf("expected aliases gone after unbind: %s", statusAfterUnbind)
	}
}

func TestCLISessionLifecycleEval(t *testing.T) {
	env := newEvalEnv(t)
	if _, _, err := runHasp(t, env, "", "init"); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	if _, _, err := runHasp(t, env, "", "set", "--name", "api_token", "--value", "abc123"); err != nil {
		t.Fatalf("set failed: %v", err)
	}
	if _, _, err := runHasp(t, env, "", "project", "bind", "--project-root", env.projectRoot, "--alias", "secret_01=api_token"); err != nil {
		t.Fatalf("project bind failed: %v", err)
	}

	revokedToken := openRuntimeSession(t, env, env.projectRoot, int(runtime.DefaultSessionTTL.Seconds()))
	revokeRuntimeSession(t, env, revokedToken)
	if _, _, err := runHasp(t, env, "", "run", "--project-root", env.projectRoot, "--session-token", revokedToken, "--env", "API_TOKEN=secret_01", "--", "true"); err == nil {
		t.Fatal("run with revoked session unexpectedly succeeded")
	}

	expiredToken := openRuntimeSession(t, env, env.projectRoot, 1)
	time.Sleep(2 * time.Second)
	if _, _, err := runHasp(t, env, "", "write-env", "--project-root", env.projectRoot, "--session-token", expiredToken, "--output", filepath.Join(env.projectRoot, ".env"), "--env", "API_TOKEN=secret_01"); err == nil {
		t.Fatal("write-env with expired session unexpectedly succeeded")
	}
}

func TestCLIProjectAdoptEval(t *testing.T) {
	env := newEvalEnv(t)
	if _, _, err := runHasp(t, env, "", "init"); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	baseDir := t.TempDir()
	repoA := filepath.Join(baseDir, "repo-a")
	repoB := filepath.Join(baseDir, "repo-b")
	plainDir := filepath.Join(baseDir, "plain")
	if err := os.MkdirAll(repoA, 0o755); err != nil {
		t.Fatalf("mkdir repoA: %v", err)
	}
	if err := os.MkdirAll(repoB, 0o755); err != nil {
		t.Fatalf("mkdir repoB: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(plainDir, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir plain: %v", err)
	}
	initGitRepo(t, repoA)
	initGitRepo(t, repoB)

	autoProtect := true
	autoInstallHooks := false
	if err := paths.SaveConfig(paths.CLIConfig{
		HomeDir:              env.home,
		AutoProtectRepos:     &autoProtect,
		AutoInstallHooks:     &autoInstallHooks,
		DefaultCapturePolicy: "access",
	}); err != nil {
		t.Fatalf("save config: %v", err)
	}

	stdout, _, err := runHasp(t, env, "", "project", "adopt", "--under", baseDir, "--preview")
	if err != nil {
		t.Fatalf("project adopt preview failed: %v", err)
	}
	preview := parseJSONMap(t, stdout)
	candidates, ok := preview["candidates"].([]any)
	if !ok || len(candidates) != 2 {
		t.Fatalf("expected two repo candidates, got %v", preview)
	}

	stdout, _, err = runHasp(t, env, "", "project", "adopt", "--under", baseDir)
	if err != nil {
		t.Fatalf("project adopt failed: %v", err)
	}
	adopted := parseJSONMap(t, stdout)
	if adopted["adopted_count"].(float64) != 2 {
		t.Fatalf("expected adopted_count 2, got %v", adopted)
	}

	statusOut, _, err := runHasp(t, env, "", "project", "status", "--project-root", repoA)
	if err != nil {
		t.Fatalf("project status after adopt failed: %v", err)
	}
	status := parseJSONMap(t, statusOut)
	binding, ok := status["binding"].(map[string]any)
	if !ok || strings.TrimSpace(binding["id"].(string)) == "" {
		t.Fatalf("expected bound project after adopt, got %v", status)
	}
}
