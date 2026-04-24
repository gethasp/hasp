package app

import (
	"bytes"
	"context"
	"errors"
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

func TestRuntimeCommandUsageErrorsAndExportRestoreRoundTrip(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	t.Setenv("HASP_BACKUP_PASSPHRASE", "backup-passphrase")

	keyring := &memorySetupKeyring{}
	origNewStore := newVaultStoreFn
	defer func() { newVaultStoreFn = origNewStore }()
	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set: %v", err)
	}

	if err := exportBackupCommand(context.Background(), []string{}, io.Discard); err == nil {
		t.Fatal("expected export-backup usage error")
	}
	backupPath := filepath.Join(t.TempDir(), "hasp.backup.json")
	if err := exportBackupCommand(context.Background(), []string{"--output", backupPath}, io.Discard); err != nil {
		t.Fatalf("export-backup command: %v", err)
	}

	restoreHome := t.TempDir()
	t.Setenv("HASP_HOME", restoreHome)
	t.Setenv("HASP_MASTER_PASSWORD", "restored-password")
	if err := restoreBackupCommand(context.Background(), []string{}, io.Discard); err == nil {
		t.Fatal("expected restore-backup usage error")
	}
	if err := restoreBackupCommand(context.Background(), []string{"--input", backupPath, "--recovery-passphrase", "backup-passphrase", "--master-password", "restored-password"}, io.Discard); err != nil {
		t.Fatalf("restore-backup command: %v", err)
	}

	var stdout bytes.Buffer
	starter := newDaemonTestStarter(t)
	if err := pingCommand(context.Background(), &stdout, starter); err != nil {
		t.Fatalf("ping command: %v", err)
	}
	if err := statusCommand(context.Background(), &stdout, starter); err != nil {
		t.Fatalf("status command: %v", err)
	}
	var daemonHelp bytes.Buffer
	if err := daemonCommand(context.Background(), []string{}, &daemonHelp, starter); err != nil {
		t.Fatalf("expected daemon help, got %v", err)
	}
	if !strings.Contains(daemonHelp.String(), "Manage the local runtime daemon") {
		t.Fatalf("expected daemon help output, got %q", daemonHelp.String())
	}
	var sessionHelp bytes.Buffer
	if err := sessionCommand(context.Background(), []string{}, &sessionHelp, starter); err != nil {
		t.Fatalf("expected session help, got %v", err)
	}
	if !strings.Contains(sessionHelp.String(), "Work with broker sessions directly") {
		t.Fatalf("expected session help output, got %q", sessionHelp.String())
	}
}

func TestDaemonCommandStartBranch(t *testing.T) {
	homeDir := t.TempDir()
	socketPath := filepath.Join("/tmp", fmt.Sprintf("hasp-app-start-%d.sock", time.Now().UnixNano()))
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_SOCKET", socketPath)
	t.Setenv("HASP_TEST_HELPER_DAEMON", "1")
	t.Cleanup(func() {
		_ = os.Remove(socketPath)
	})

	if err := daemonCommand(context.Background(), []string{"start"}, io.Discard, &fakeStarter{}); err != nil {
		t.Fatalf("daemon start: %v", err)
	}

	manager, err := runtime.NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	waitForSocket(t, manager.SocketPath(), make(chan error))
	if err := manager.StopDaemon(); err != nil {
		t.Fatalf("stop daemon: %v", err)
	}
}

func TestSessionGrantPlaintextCommand(t *testing.T) {
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
	if err := Run(context.Background(), []string{"secret", "add", "--project-root", projectRoot, "API_TOKEN=abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}

	starter := newDaemonTestStarter(t)
	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer client.Close()
	reply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "agent",
		ProjectRoot:  projectRoot,
		TTLSeconds:   int(runtime.DefaultSessionTTL.Seconds()),
		AgentSafe:    true,
		ConsumerName: "claude-code",
	})
	if err != nil {
		t.Fatalf("open session: %v", err)
	}

	origApprove := sessionGrantPlaintextApproveFn
	defer func() { sessionGrantPlaintextApproveFn = origApprove }()
	sessionGrantPlaintextApproveFn = func(runtime.SessionView, string, store.PlaintextAction) error { return nil }

	var out bytes.Buffer
	if err := sessionGrantPlaintextCommand(context.Background(), []string{"--token", reply.SessionToken, "--item", "API_TOKEN", "--action", "reveal", "--json"}, &out, starter); err != nil {
		t.Fatalf("grant plaintext command: %v", err)
	}
	if !strings.Contains(out.String(), "\"plaintext_action\":\"reveal\"") {
		t.Fatalf("unexpected json output %q", out.String())
	}

	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if !handle.PlaintextGrantActive(reply.SessionToken, "API_TOKEN", store.PlaintextReveal) {
		t.Fatal("expected active plaintext grant")
	}

	nonAgentReply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:   "human",
		ProjectRoot: projectRoot,
		TTLSeconds:  int(runtime.DefaultSessionTTL.Seconds()),
	})
	if err != nil {
		t.Fatalf("open non-agent session: %v", err)
	}
	if err := sessionGrantPlaintextCommand(context.Background(), []string{"--token", nonAgentReply.SessionToken, "--item", "API_TOKEN", "--action", "copy"}, io.Discard, starter); err == nil {
		t.Fatal("expected non-agent-safe session failure")
	}
	if err := sessionGrantPlaintextCommand(context.Background(), []string{"--token", reply.SessionToken, "--item", "API_TOKEN", "--action", "bogus"}, io.Discard, starter); err == nil {
		t.Fatal("expected bad action failure")
	}
	if err := sessionGrantPlaintextCommand(context.Background(), []string{"--token", reply.SessionToken, "--item", "API_TOKEN", "--action", "reveal", "--scope", "window"}, io.Discard, starter); err == nil {
		t.Fatal("expected unsupported scope failure")
	}
	t.Setenv(envSessionToken, reply.SessionToken)
	if err := sessionGrantPlaintextCommand(context.Background(), []string{"--item", "API_TOKEN", "--action", "copy", "--json"}, io.Discard, starter); err != nil {
		t.Fatalf("expected env-token plaintext grant success: %v", err)
	}
	if err := confirmPlaintextGrant(runtime.SessionView{HostLabel: "agent", ProjectRoot: projectRoot}, "API_TOKEN", store.PlaintextReveal); err != nil {
		t.Fatalf("confirmPlaintextGrant non-darwin should no-op in tests: %v", err)
	}
}

func TestSessionGrantPlaintextCommandFailureBranches(t *testing.T) {
	lockAppSeams(t)

	if err := sessionGrantPlaintextCommand(context.Background(), []string{"--bad"}, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected parse failure")
	}
	if err := sessionGrantPlaintextCommand(context.Background(), nil, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected usage failure")
	}
	if err := sessionGrantPlaintextCommand(context.Background(), []string{"--token", "token", "--item", "API_TOKEN", "--action", "reveal"}, io.Discard, &fakeStarter{err: io.EOF}); err == nil {
		t.Fatal("expected ensureClient failure")
	}

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
	if err := Run(context.Background(), []string{"secret", "add", "--project-root", projectRoot, "API_TOKEN=abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}
	starter := newDaemonTestStarter(t)
	if err := sessionGrantPlaintextCommand(context.Background(), []string{"--token", "missing", "--item", "API_TOKEN", "--action", "reveal"}, io.Discard, starter); err == nil || !strings.Contains(err.Error(), "resolve session") {
		t.Fatalf("expected resolve session failure, got %v", err)
	}
	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer client.Close()
	reply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "agent",
		ProjectRoot:  projectRoot,
		TTLSeconds:   int(runtime.DefaultSessionTTL.Seconds()),
		AgentSafe:    true,
		ConsumerName: "claude-code",
	})
	if err != nil {
		t.Fatalf("open session: %v", err)
	}

	origApprove := sessionGrantPlaintextApproveFn
	origOpen := openVaultHandleFn
	origGet := secretGetItemFn
	origGrant := sessionGrantPlaintextUseFn
	defer func() {
		sessionGrantPlaintextApproveFn = origApprove
		openVaultHandleFn = origOpen
		secretGetItemFn = origGet
		sessionGrantPlaintextUseFn = origGrant
	}()
	sessionGrantPlaintextApproveFn = func(runtime.SessionView, string, store.PlaintextAction) error { return errors.New("approval fail") }
	if err := sessionGrantPlaintextCommand(context.Background(), []string{"--token", reply.SessionToken, "--item", "API_TOKEN", "--action", "reveal"}, io.Discard, starter); err == nil || err.Error() != "approval fail" {
		t.Fatalf("expected approval failure, got %v", err)
	}
	sessionGrantPlaintextApproveFn = func(runtime.SessionView, string, store.PlaintextAction) error { return nil }
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("vault fail") }
	if err := sessionGrantPlaintextCommand(context.Background(), []string{"--token", reply.SessionToken, "--item", "API_TOKEN", "--action", "reveal"}, io.Discard, starter); err == nil || err.Error() != "vault fail" {
		t.Fatalf("expected open vault failure, got %v", err)
	}
	openVaultHandleFn = origOpen
	secretGetItemFn = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("get fail") }
	if err := sessionGrantPlaintextCommand(context.Background(), []string{"--token", reply.SessionToken, "--item", "API_TOKEN", "--action", "reveal"}, io.Discard, starter); err == nil || err.Error() != "get fail" {
		t.Fatalf("expected get item failure, got %v", err)
	}
	secretGetItemFn = origGet
	sessionGrantPlaintextUseFn = func(*store.Handle, string, string, store.PlaintextAction, time.Duration) (store.PlaintextGrant, error) {
		return store.PlaintextGrant{}, errors.New("grant fail")
	}
	if err := sessionGrantPlaintextCommand(context.Background(), []string{"--token", reply.SessionToken, "--item", "API_TOKEN", "--action", "reveal"}, io.Discard, starter); err == nil || err.Error() != "grant fail" {
		t.Fatalf("expected plaintext grant persistence failure, got %v", err)
	}
}

func TestConfirmPlaintextGrantBranches(t *testing.T) {
	lockAppSeams(t)

	origGOOS := confirmPlaintextGrantGOOS
	origCommand := confirmPlaintextGrantCommandFn
	origUnderTest := confirmPlaintextGrantUnderTestFn
	defer func() {
		confirmPlaintextGrantGOOS = origGOOS
		confirmPlaintextGrantCommandFn = origCommand
		confirmPlaintextGrantUnderTestFn = origUnderTest
	}()
	confirmPlaintextGrantUnderTestFn = func() bool { return true }
	if err := confirmPlaintextGrant(runtime.SessionView{HostLabel: "agent", ProjectRoot: "/tmp/project"}, "API_TOKEN", store.PlaintextReveal); err != nil {
		t.Fatalf("under-test shortcut should bypass approval: %v", err)
	}
	confirmPlaintextGrantUnderTestFn = func() bool { return false }

	confirmPlaintextGrantGOOS = "darwin"
	confirmPlaintextGrantCommandFn = func(string, ...string) *exec.Cmd {
		return exec.Command("sh", "-c", "exit 0")
	}
	if err := confirmPlaintextGrant(runtime.SessionView{HostLabel: "agent", ProjectRoot: "/tmp/project"}, "API_TOKEN", store.PlaintextCopy); err != nil {
		t.Fatalf("darwin approval success: %v", err)
	}
	confirmPlaintextGrantCommandFn = func(string, ...string) *exec.Cmd {
		return exec.Command("sh", "-c", "exit 1")
	}
	if err := confirmPlaintextGrant(runtime.SessionView{HostLabel: "agent", ProjectRoot: "/tmp/project"}, "API_TOKEN", store.PlaintextCopy); err == nil {
		t.Fatal("expected darwin approval failure")
	}

	confirmPlaintextGrantGOOS = "linux"
	origStdin := os.Stdin
	origCharDevice := secretIsCharDeviceFn
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		secretIsCharDeviceFn = origCharDevice
	}()
	secretIsCharDeviceFn = func(*os.File) bool { return true }
	if _, err := w.WriteString("grant reveal API_TOKEN\n"); err != nil {
		t.Fatalf("write prompt input: %v", err)
	}
	if err := w.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Fatalf("close writer: %v", err)
	}
	if err := confirmPlaintextGrant(runtime.SessionView{HostLabel: "agent", ProjectRoot: ""}, "API_TOKEN", store.PlaintextReveal); err != nil {
		t.Fatalf("tty fallback approval success: %v", err)
	}

	secretIsCharDeviceFn = func(*os.File) bool { return false }
	if err := confirmPlaintextGrant(runtime.SessionView{HostLabel: "agent", ProjectRoot: ""}, "API_TOKEN", store.PlaintextReveal); err == nil {
		t.Fatal("expected non-interactive approval failure")
	}

	secretIsCharDeviceFn = func(*os.File) bool { return true }
	r2, w2, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe mismatch: %v", err)
	}
	defer r2.Close()
	defer w2.Close()
	os.Stdin = r2
	if _, err := w2.WriteString("wrong phrase\n"); err != nil {
		t.Fatalf("write mismatch phrase: %v", err)
	}
	if err := w2.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Fatalf("close mismatch writer: %v", err)
	}
	if err := confirmPlaintextGrant(runtime.SessionView{HostLabel: "agent", ProjectRoot: ""}, "API_TOKEN", store.PlaintextReveal); err == nil {
		t.Fatal("expected approval cancellation on mismatched phrase")
	}

	origStdout := os.Stdout
	r3, w3, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	if err := w3.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	os.Stdout = w3
	defer func() {
		os.Stdout = origStdout
		_ = r3.Close()
	}()
	if err := confirmPlaintextGrant(runtime.SessionView{HostLabel: "agent", ProjectRoot: ""}, "API_TOKEN", store.PlaintextReveal); err == nil {
		t.Fatal("expected stdout write failure on approval prompt")
	}
	os.Stdout = origStdout

	r4, w4, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdin read fail: %v", err)
	}
	_ = r4.Close()
	os.Stdin = r4
	defer func() { _ = w4.Close() }()
	secretIsCharDeviceFn = func(*os.File) bool { return true }
	if err := confirmPlaintextGrant(runtime.SessionView{HostLabel: "agent", ProjectRoot: ""}, "API_TOKEN", store.PlaintextReveal); err == nil {
		t.Fatal("expected read failure/cancel on closed stdin")
	}
}
