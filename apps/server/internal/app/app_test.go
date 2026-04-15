package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type fakeStarter struct {
	ensureCalls int
	client      *runtime.Client
	err         error
}

func (f *fakeStarter) EnsureDaemon(context.Context) error {
	f.ensureCalls++
	return f.err
}

func (f *fakeStarter) Connect(context.Context) (*runtime.Client, error) {
	return f.client, f.err
}

type daemonTestStarter struct {
	manager *runtime.Manager
}

func (d *daemonTestStarter) EnsureDaemon(context.Context) error {
	return nil
}

func (d *daemonTestStarter) Connect(ctx context.Context) (*runtime.Client, error) {
	return runtime.Dial(ctx, d.manager.SocketPath())
}

func TestHelp(t *testing.T) {
	var stdout bytes.Buffer
	if err := runWithStarter(context.Background(), nil, bytes.NewBuffer(nil), &stdout, &stdout, &fakeStarter{}); err != nil {
		t.Fatalf("run help: %v", err)
	}
	if stdout.Len() == 0 {
		t.Fatalf("expected help output")
	}
}

func TestRunUnknownCommandAndHelpAlias(t *testing.T) {
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"help"}, bytes.NewBuffer(nil), &stdout, &stdout); err != nil {
		t.Fatalf("run help alias: %v", err)
	}
	if stdout.Len() == 0 {
		t.Fatal("expected help output")
	}
	if err := Run(context.Background(), []string{"unknown-command"}, bytes.NewBuffer(nil), &stdout, &stdout); err == nil {
		t.Fatal("expected unknown command error")
	}
}

func TestRunPropagatesStarterConstructionFailure(t *testing.T) {
	lockAppSeams(t)
	orig := newRuntimeStarterFn
	defer func() { newRuntimeStarterFn = orig }()
	newRuntimeStarterFn = func() (*runtimeStarter, error) { return nil, io.EOF }
	if err := Run(context.Background(), []string{"help"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected starter construction failure")
	}
}

func TestInitAndImportCommands(t *testing.T) {
	homeDir := t.TempDir()
	envPath := filepath.Join(t.TempDir(), ".env")
	projectRoot := t.TempDir()
	if err := os.WriteFile(envPath, []byte("API_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)

	var initOut bytes.Buffer
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), &initOut, &initOut); err != nil {
		t.Fatalf("run init: %v", err)
	}

	var importOut bytes.Buffer
	if err := Run(context.Background(), []string{"import", envPath}, bytes.NewBuffer(nil), &importOut, &importOut); err != nil {
		t.Fatalf("run import: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(importOut.Bytes(), &payload); err != nil {
		t.Fatalf("decode import output: %v", err)
	}

	var captureOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"capture", "--name", "session_token", "--value", "top-secret", "--project-root", projectRoot, "--grant-project", "window", "--grant-write"}, bytes.NewBuffer(nil), &captureOut, &captureOut, starter); err != nil {
		t.Fatalf("run capture: %v", err)
	}

	var redactOut bytes.Buffer
	if err := Run(context.Background(), []string{"redact"}, bytes.NewBufferString("token=top-secret"), &redactOut, &redactOut); err != nil {
		t.Fatalf("run redact: %v", err)
	}
	if redactOut.String() == "token=top-secret" {
		t.Fatalf("expected redaction to change output")
	}

	var auditOut bytes.Buffer
	if err := Run(context.Background(), []string{"audit"}, bytes.NewBuffer(nil), &auditOut, &auditOut); err != nil {
		t.Fatalf("run audit verify: %v", err)
	}
}

func TestProjectBindStatusAndUnbindCommands(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	projectRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectRoot, ".gitignore"), []byte(""), 0o600); err != nil {
		t.Fatalf("write gitignore: %v", err)
	}
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	var initOut bytes.Buffer
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), &initOut, &initOut); err != nil {
		t.Fatalf("run init: %v", err)
	}

	var setOut bytes.Buffer
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123"}, bytes.NewBuffer(nil), &setOut, &setOut); err != nil {
		t.Fatalf("run set: %v", err)
	}

	var bindOut bytes.Buffer
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "secret_01=api_token"}, bytes.NewBuffer(nil), &bindOut, &bindOut); err != nil {
		t.Fatalf("run project bind: %v", err)
	}
	hookData, err := os.ReadFile(filepath.Join(projectRoot, ".git", "hooks", "pre-commit"))
	if err != nil {
		t.Fatalf("expected installed hook: %v", err)
	}
	if !strings.Contains(string(hookData), "HASP-MANAGED-HOOK") {
		t.Fatalf("expected HASP hook marker")
	}

	var statusOut bytes.Buffer
	if err := Run(context.Background(), []string{"project", "status", "--project-root", projectRoot}, bytes.NewBuffer(nil), &statusOut, &statusOut); err != nil {
		t.Fatalf("run project status: %v", err)
	}
	var statusPayload map[string]any
	if err := json.Unmarshal(statusOut.Bytes(), &statusPayload); err != nil {
		t.Fatalf("decode project status: %v", err)
	}

	var unbindOut bytes.Buffer
	if err := Run(context.Background(), []string{"project", "unbind", "--project-root", projectRoot}, bytes.NewBuffer(nil), &unbindOut, &unbindOut); err != nil {
		t.Fatalf("run project unbind: %v", err)
	}

	statusOut.Reset()
	if err := Run(context.Background(), []string{"project", "status", "--project-root", projectRoot}, bytes.NewBuffer(nil), &statusOut, &statusOut); err != nil {
		t.Fatalf("run project status after unbind: %v", err)
	}
	statusPayload = map[string]any{}
	if err := json.Unmarshal(statusOut.Bytes(), &statusPayload); err != nil {
		t.Fatalf("decode project status after unbind: %v", err)
	}
	if visible, ok := statusPayload["visible"].([]any); ok && len(visible) != 0 {
		t.Fatalf("expected no visible references after unbind")
	}
}

func TestExportAndRestoreBackupCommands(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	var initOut bytes.Buffer
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), &initOut, &initOut); err != nil {
		t.Fatalf("run init: %v", err)
	}

	var setOut bytes.Buffer
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123"}, bytes.NewBuffer(nil), &setOut, &setOut); err != nil {
		t.Fatalf("run set: %v", err)
	}

	backupPath := filepath.Join(t.TempDir(), "hasp.backup.json")
	var exportOut bytes.Buffer
	if err := Run(context.Background(), []string{"export-backup", "--output", backupPath, "--recovery-passphrase", "backup-passphrase"}, bytes.NewBuffer(nil), &exportOut, &exportOut); err != nil {
		t.Fatalf("run export-backup: %v", err)
	}

	restoreHome := t.TempDir()
	t.Setenv("HASP_HOME", restoreHome)
	t.Setenv("HASP_MASTER_PASSWORD", "restored-password")

	var restoreOut bytes.Buffer
	if err := Run(context.Background(), []string{"restore-backup", "--input", backupPath, "--recovery-passphrase", "backup-passphrase"}, bytes.NewBuffer(nil), &restoreOut, &restoreOut); err != nil {
		t.Fatalf("run restore-backup: %v", err)
	}

	restoreStore, err := store.New(store.NewDefaultKeyring())
	if err != nil {
		t.Fatalf("new restored store: %v", err)
	}
	handle, err := restoreStore.OpenWithPassword(context.Background(), "restored-password")
	if err != nil {
		t.Fatalf("open restored store: %v", err)
	}
	item, err := handle.GetItem("api_token")
	if err != nil {
		t.Fatalf("get restored item: %v", err)
	}
	if string(item.Value) != "abc123" {
		t.Fatalf("restored value = %q", string(item.Value))
	}
}

func TestRunWriteEnvCheckRepoAndTUICommands(t *testing.T) {
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectRoot, ".gitignore"), []byte(""), 0o600); err != nil {
		t.Fatalf("write gitignore: %v", err)
	}
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)

	var initOut bytes.Buffer
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), &initOut, &initOut); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set api_token: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "db_url", "--value", "postgres://localhost"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set db_url: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "secret_01=api_token", "--alias", "secret_02=db_url"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run project bind: %v", err)
	}

	var runOut bytes.Buffer
	var runErr bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"run", "--project-root", projectRoot, "--env", "API_TOKEN=secret_01", "--grant-project", "window", "--grant-secret", "session", "--", "sh", "-c", "printf '%s' \"$API_TOKEN\""}, bytes.NewBuffer(nil), &runOut, &runErr, starter); err != nil {
		t.Fatalf("run command: %v", err)
	}
	if strings.Contains(runOut.String(), "abc123") {
		t.Fatalf("expected run output to be redacted, got %q", runOut.String())
	}

	var writeEnvOut bytes.Buffer
	var writeEnvErr bytes.Buffer
	envPath := filepath.Join(projectRoot, ".env.local")
	if err := runWithStarter(context.Background(), []string{"write-env", "--project-root", projectRoot, "--output", envPath, "--env", "API_TOKEN=secret_01", "--env", "DATABASE_URL=secret_02", "--grant-project", "window", "--grant-secret", "session", "--grant-convenience", "window"}, bytes.NewBuffer(nil), &writeEnvOut, &writeEnvErr, starter); err != nil {
		t.Fatalf("write-env command: %v", err)
	}
	if _, err := os.Stat(envPath); err != nil {
		t.Fatalf("expected env file: %v", err)
	}

	var checkOut bytes.Buffer
	err := Run(context.Background(), []string{"check-repo", "--project-root", projectRoot}, bytes.NewBuffer(nil), &checkOut, &checkOut)
	if err == nil {
		t.Fatal("expected check-repo to report managed secrets in project files")
	}

	var tuiOut bytes.Buffer
	if err := Run(context.Background(), []string{"tui", "--project-root", projectRoot}, bytes.NewBuffer(nil), &tuiOut, &tuiOut); err != nil {
		t.Fatalf("tui command: %v", err)
	}
	if !strings.Contains(tuiOut.String(), "HASP TUI") {
		t.Fatalf("expected tui output, got %q", tuiOut.String())
	}
}

func TestCaptureRequiresExplicitWriteGrant(t *testing.T) {
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	var stdout bytes.Buffer
	err := runWithStarter(context.Background(), []string{"capture", "--name", "api_token", "--value", "abc123", "--project-root", projectRoot, "--grant-project", "window"}, bytes.NewBuffer(nil), &stdout, &stdout, starter)
	if err == nil || !strings.Contains(err.Error(), "capture write grant required") {
		t.Fatalf("expected explicit write grant error, got %v", err)
	}
}

func TestRunRejectsUnknownSessionToken(t *testing.T) {
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "secret_01=api_token"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run project bind: %v", err)
	}

	var stdout bytes.Buffer
	err := runWithStarter(context.Background(), []string{"run", "--project-root", projectRoot, "--session-token", "invented-token", "--env", "API_TOKEN=secret_01", "--", "true"}, bytes.NewBuffer(nil), &stdout, &stdout, starter)
	if err == nil || !strings.Contains(err.Error(), "resolve session") {
		t.Fatalf("expected session resolution error, got %v", err)
	}
}

func TestInjectCommandWrapper(t *testing.T) {
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "cert_file", "--kind", "file", "--value", "certificate-data"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set cert_file: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "file_01=cert_file"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("project bind: %v", err)
	}

	var stdout bytes.Buffer
	if err := injectCommand(context.Background(), []string{"--project-root", projectRoot, "--file", "CERT_PATH=file_01", "--grant-project", "window", "--grant-secret", "session", "--", "sh", "-c", "cat \"$CERT_PATH\""}, &stdout, &stdout, starter); err != nil {
		t.Fatalf("inject command: %v", err)
	}
	if strings.Contains(stdout.String(), "certificate-data") {
		t.Fatalf("expected redacted output, got %s", stdout.String())
	}
}

func TestRunUsesRealRuntimeStarterForPingStatusAndSessions(t *testing.T) {
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_SOCKET", filepath.Join("/tmp", fmt.Sprintf("hasp-real-%d.sock", time.Now().UnixNano())))
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	manager, err := runtime.NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.RunDaemon(ctx)
	}()
	waitForSocket(t, manager.SocketPath(), errCh)
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("daemon exited: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for daemon shutdown")
		}
	})
	starter := &runtimeStarter{manager: manager}

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	var pingOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"ping"}, bytes.NewBuffer(nil), &pingOut, &pingOut, starter); err != nil {
		t.Fatalf("run ping: %v", err)
	}
	if !strings.Contains(pingOut.String(), "hasp") {
		t.Fatalf("unexpected ping output: %s", pingOut.String())
	}

	var statusOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"status"}, bytes.NewBuffer(nil), &statusOut, &statusOut, starter); err != nil {
		t.Fatalf("run status: %v", err)
	}
	if !strings.Contains(statusOut.String(), "active_sessions") {
		t.Fatalf("unexpected status output: %s", statusOut.String())
	}

	var openOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"session", "open", "--host-label", "app-test", "--project-root", projectRoot}, bytes.NewBuffer(nil), &openOut, &openOut, starter); err != nil {
		t.Fatalf("session open: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(openOut.Bytes(), &payload); err != nil {
		t.Fatalf("decode session open: %v", err)
	}
	sessionID, _ := payload["session_id"].(string)
	if sessionID == "" {
		t.Fatalf("expected session_id in output: %v", payload)
	}

	manager, err = runtime.NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	client, err := runtime.Dial(context.Background(), manager.SocketPath())
	if err != nil {
		t.Fatalf("dial runtime: %v", err)
	}
	defer client.Close()
	sessionReply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:   "app-test",
		ProjectRoot: projectRoot,
		TTLSeconds:  int(runtime.DefaultSessionTTL.Seconds()),
	})
	if err != nil {
		t.Fatalf("open session via client: %v", err)
	}

	var resolveOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"session", "resolve", "--token", sessionReply.SessionToken}, bytes.NewBuffer(nil), &resolveOut, &resolveOut, starter); err != nil {
		t.Fatalf("session resolve: %v", err)
	}
	if !strings.Contains(resolveOut.String(), sessionReply.SessionID) {
		t.Fatalf("unexpected resolve output: %s", resolveOut.String())
	}

	var revokeOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"session", "revoke", "--token", sessionReply.SessionToken}, bytes.NewBuffer(nil), &revokeOut, &revokeOut, starter); err != nil {
		t.Fatalf("session revoke: %v", err)
	}
	if !strings.Contains(revokeOut.String(), "revoked") {
		t.Fatalf("unexpected revoke output: %s", revokeOut.String())
	}

	var daemonOut bytes.Buffer
	if err := daemonCommand(context.Background(), []string{"status"}, &daemonOut, starter); err != nil {
		t.Fatalf("daemon status: %v", err)
	}
	if !strings.Contains(daemonOut.String(), "active_sessions") {
		t.Fatalf("unexpected daemon status output: %s", daemonOut.String())
	}

	if err := daemonCommand(context.Background(), []string{"start"}, io.Discard, starter); err != nil {
		t.Fatalf("daemon start: %v", err)
	}
	if err := daemonCommand(context.Background(), []string{"unknown"}, io.Discard, starter); err == nil {
		t.Fatal("expected daemon unknown subcommand error")
	}
	if err := sessionCommand(context.Background(), []string{"unknown"}, io.Discard, starter); err == nil {
		t.Fatal("expected session unknown subcommand error")
	}
	if err := projectCommand(context.Background(), []string{"unknown"}, io.Discard); err == nil {
		t.Fatal("expected project unknown subcommand error")
	}
}

func run(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

func newDaemonTestStarter(t *testing.T) starter {
	t.Helper()

	t.Setenv("HASP_SOCKET", filepath.Join("/tmp", fmt.Sprintf("hasp-app-%d.sock", time.Now().UnixNano())))
	manager, err := runtime.NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.RunDaemon(ctx)
	}()
	waitForSocket(t, manager.SocketPath(), errCh)
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("daemon exited: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for test daemon shutdown")
		}
	})
	return &daemonTestStarter{manager: manager}
}

func waitForSocket(t *testing.T, socketPath string, errCh <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("daemon startup failed: %v", err)
			}
			t.Fatalf("daemon exited before socket became available")
		default:
		}
		if _, err := os.Stat(socketPath); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for socket %s", socketPath)
}
