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

	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type errReader struct {
	err error
}

func (r errReader) Read([]byte) (int, error) {
	return 0, r.err
}

type errWriter struct {
	err error
}

func (w errWriter) Write([]byte) (int, error) {
	return 0, w.err
}

type fixedClientStarter struct {
	client *runtime.Client
}

func (s fixedClientStarter) EnsureDaemon(context.Context) error {
	return nil
}

func (s fixedClientStarter) Connect(context.Context) (*runtime.Client, error) {
	return s.client, nil
}

func TestRunVersionMCPAndStarterConstructionSuccess(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_SOCKET", filepath.Join(t.TempDir(), "daemon.sock"))
	starter, err := newRuntimeStarter()
	if err != nil {
		t.Fatalf("new runtime starter: %v", err)
	}
	if starter.manager == nil {
		t.Fatal("expected manager on runtime starter")
	}

	var versionOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"version"}, bytes.NewBuffer(nil), &versionOut, io.Discard, &fakeStarter{}); err != nil {
		t.Fatalf("run version: %v", err)
	}
	if !strings.Contains(versionOut.String(), runtime.Version()) {
		t.Fatalf("expected version output, got %q", versionOut.String())
	}

	var mcpOut bytes.Buffer
	mcpIn := bytes.NewBufferString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n")
	if err := runWithStarter(context.Background(), []string{"mcp"}, mcpIn, &mcpOut, io.Discard, &fakeStarter{}); err != nil {
		t.Fatalf("run mcp: %v", err)
	}
	if !strings.Contains(mcpOut.String(), "protocolVersion") {
		t.Fatalf("expected mcp response, got %q", mcpOut.String())
	}
}

func TestNewRuntimeStarterFailsWithoutResolvableHome(t *testing.T) {
	t.Setenv("HASP_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "relative-config-home")
	if _, err := newRuntimeStarter(); err == nil {
		t.Fatal("expected runtime starter construction failure without home")
	}
}

func TestUsageAndMissingPasswordBranches(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "")

	var projectHelp bytes.Buffer
	if err := projectCommand(context.Background(), nil, &projectHelp); err != nil {
		t.Fatalf("expected project command help, got %v", err)
	}
	if !strings.Contains(projectHelp.String(), "Manage repo boundaries") {
		t.Fatalf("expected project help output, got %q", projectHelp.String())
	}
	if err := importCommand(context.Background(), nil, io.Discard); err == nil {
		t.Fatal("expected import usage error")
	}
	if err := setCommand(context.Background(), nil, io.Discard); err == nil {
		t.Fatal("expected set usage error")
	}
	if err := captureCommand(context.Background(), nil, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected capture usage error")
	}
	if err := projectBindCommand(context.Background(), []string{"--alias", "secret_01=item_01", "--hooks=false"}, io.Discard); err == nil {
		t.Fatal("expected project bind master password error")
	}
	if err := projectStatusCommand(context.Background(), nil, io.Discard); err == nil {
		t.Fatal("expected project status master password error")
	}
	if err := projectUnbindCommand(context.Background(), nil, io.Discard); err == nil {
		t.Fatal("expected project unbind master password error")
	}
	if err := initCommand(context.Background(), io.Discard); err == nil {
		t.Fatal("expected init master password error")
	}
	if err := exportBackupCommand(context.Background(), []string{"--output", filepath.Join(t.TempDir(), "backup.json")}, io.Discard); err == nil {
		t.Fatal("expected export backup usage error without passphrase")
	}
	if err := restoreBackupCommand(context.Background(), []string{"--input", filepath.Join(t.TempDir(), "backup.json"), "--recovery-passphrase", "recovery"}, io.Discard); err == nil {
		t.Fatal("expected restore backup usage error without master password")
	}
	if _, err := loadMasterPassword(); err == nil {
		t.Fatal("expected master password error")
	}
}

func TestResolveValueAndRedactReaderErrorBranches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "value.txt")
	if err := os.WriteFile(path, []byte("file-data"), 0o600); err != nil {
		t.Fatalf("write value file: %v", err)
	}
	value, err := resolveValue("", path)
	if err != nil {
		t.Fatalf("resolve from file: %v", err)
	}
	if string(value) != "file-data" {
		t.Fatalf("resolved value = %q", string(value))
	}

	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	readErr := errors.New("read failure")
	if err := redactCommand(context.Background(), errReader{err: readErr}, io.Discard); !errors.Is(err, readErr) {
		t.Fatalf("expected redact read error, got %v", err)
	}
}

func TestProjectBindHookFailureAndHooklessSuccess(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	plainProject := t.TempDir()
	var hooklessOut bytes.Buffer
	if err := projectBindCommand(context.Background(), []string{"--project-root", plainProject, "--hooks=false", "--alias", "secret_01=item_01"}, &hooklessOut); err != nil {
		t.Fatalf("project bind without hooks: %v", err)
	}

	gitProject := t.TempDir()
	if out, err := run("git", "-C", gitProject, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	hooksPath := filepath.Join(gitProject, ".git", "hooks")
	if err := os.RemoveAll(hooksPath); err != nil {
		t.Fatalf("remove hooks dir: %v", err)
	}
	if err := os.WriteFile(hooksPath, []byte("not-a-dir"), 0o600); err != nil {
		t.Fatalf("write hooks path file: %v", err)
	}
	if err := projectBindCommand(context.Background(), []string{"--project-root", gitProject, "--alias", "secret_01=item_01"}, io.Discard); err == nil {
		t.Fatal("expected project bind hook install failure")
	}
}

func TestRuntimeSessionAndDaemonEdgeCases(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	if err := sessionOpenCommand(context.Background(), []string{"--bad"}, io.Discard, starter); err == nil {
		t.Fatal("expected session open parse error")
	}
	if err := sessionResolveCommand(context.Background(), []string{}, io.Discard, starter); err == nil {
		t.Fatal("expected session resolve usage error")
	}
	if err := sessionResolveCommand(context.Background(), []string{"--token", "bogus"}, io.Discard, starter); err == nil {
		t.Fatal("expected session resolve runtime error")
	}
	if err := sessionRevokeCommand(context.Background(), []string{}, io.Discard, starter); err == nil {
		t.Fatal("expected session revoke usage error")
	}
	if err := sessionRevokeCommand(context.Background(), []string{"--token", "bogus"}, io.Discard, starter); err == nil {
		t.Fatal("expected session revoke runtime error")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := daemonCommand(ctx, []string{"serve"}, io.Discard, starter); err != nil {
		t.Fatalf("daemon serve with canceled context: %v", err)
	}
	if err := daemonCommand(context.Background(), []string{"stop"}, io.Discard, starter); err == nil {
		t.Fatal("expected daemon stop error without pid file")
	}

	t.Setenv("HASP_HOME", "")
	t.Setenv("HOME", "")
	if err := daemonCommand(context.Background(), []string{"status"}, io.Discard, starter); err == nil {
		t.Fatal("expected daemon manager construction failure without home")
	}
}

func TestParseGrantScopeAndPathInsideProjectAdditionalCases(t *testing.T) {
	if scope := parseGrantScope(" once "); scope != store.GrantOnce {
		t.Fatalf("expected grant once, got %q", scope)
	}
	root := t.TempDir()
	if !pathInsideProject(root, root) {
		t.Fatal("expected root to be inside project")
	}
	if pathInsideProject(filepath.Join(t.TempDir(), "elsewhere"), root) {
		t.Fatal("expected unrelated path to be outside project")
	}
}

func TestProjectStatusAndUnbindDirectBranches(t *testing.T) {
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set: %v", err)
	}
	if err := projectBindCommand(context.Background(), []string{"--project-root", projectRoot, "--hooks=false", "--alias", "secret_01=api_token"}, io.Discard); err != nil {
		t.Fatalf("project bind: %v", err)
	}
	if err := projectBindCommand(context.Background(), []string{"--project-root", projectRoot, "--hooks=false", "--alias", "secret_01=api_token"}, errWriter{err: errors.New("project bind encode failure")}); err == nil {
		t.Fatal("expected project bind encode failure")
	}
	if err := projectStatusCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected project status parse error")
	}
	statusErr := errors.New("status writer failure")
	if err := projectStatusCommand(context.Background(), []string{"--project-root", projectRoot}, errWriter{err: statusErr}); !errors.Is(err, statusErr) {
		t.Fatalf("expected project status writer failure, got %v", err)
	}
	if err := projectUnbindCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected project unbind parse error")
	}
	unbindErr := errors.New("unbind writer failure")
	if err := projectUnbindCommand(context.Background(), []string{"--project-root", projectRoot}, errWriter{err: unbindErr}); !errors.Is(err, unbindErr) {
		t.Fatalf("expected project unbind writer failure, got %v", err)
	}
	if err := projectUnbindCommand(context.Background(), []string{"--project-root", projectRoot}, io.Discard); err != nil {
		t.Fatalf("expected idempotent second unbind, got %v", err)
	}
	t.Setenv("HASP_MASTER_PASSWORD", "wrong password")
	if err := projectStatusCommand(context.Background(), []string{"--project-root", projectRoot}, io.Discard); err == nil {
		t.Fatal("expected project status wrong-password failure")
	}
	if err := projectUnbindCommand(context.Background(), []string{"--project-root", projectRoot}, io.Discard); err == nil {
		t.Fatal("expected project unbind wrong-password failure")
	}
}

func TestRuntimeCommandWriterBranches(t *testing.T) {
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set: %v", err)
	}
	if err := projectBindCommand(context.Background(), []string{"--project-root", projectRoot, "--hooks=false", "--alias", "secret_01=api_token"}, io.Discard); err != nil {
		t.Fatalf("project bind: %v", err)
	}

	pingErr := errors.New("ping writer failure")
	if err := pingCommand(context.Background(), errWriter{err: pingErr}, starter); !errors.Is(err, pingErr) {
		t.Fatalf("expected ping writer failure, got %v", err)
	}
	if err := pingCommand(context.Background(), io.Discard, &fakeStarter{err: io.EOF}); err == nil {
		t.Fatal("expected ping ensureClient failure")
	}
	statusErr := errors.New("status writer failure")
	if err := statusCommand(context.Background(), errWriter{err: statusErr}, starter); !errors.Is(err, statusErr) {
		t.Fatalf("expected status writer failure, got %v", err)
	}
	if err := statusCommand(context.Background(), io.Discard, &fakeStarter{err: io.EOF}); err == nil {
		t.Fatal("expected status ensureClient failure")
	}
	if err := sessionOpenCommand(context.Background(), []string{"--project-root", projectRoot, "--bad"}, io.Discard, starter); err == nil {
		t.Fatal("expected session open parse error")
	}
	sessionOpenErr := errors.New("session open writer failure")
	if err := sessionOpenCommand(context.Background(), []string{"--project-root", projectRoot}, errWriter{err: sessionOpenErr}, starter); !errors.Is(err, sessionOpenErr) {
		t.Fatalf("expected session open writer failure, got %v", err)
	}
	if err := sessionOpenCommand(context.Background(), []string{"--project-root", projectRoot}, io.Discard, &fakeStarter{err: io.EOF}); err == nil {
		t.Fatal("expected session open ensureClient failure")
	}

	manager, err := runtime.NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	client, err := runtime.Dial(context.Background(), manager.SocketPath())
	if err != nil {
		t.Fatalf("dial runtime: %v", err)
	}
	defer client.Close()
	reply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:   "coverage",
		ProjectRoot: projectRoot,
		TTLSeconds:  int(runtime.DefaultSessionTTL.Seconds()),
	})
	if err != nil {
		t.Fatalf("open session: %v", err)
	}

	if err := sessionResolveCommand(context.Background(), []string{"--bad"}, io.Discard, starter); err == nil {
		t.Fatal("expected session resolve parse error")
	}
	sessionResolveErr := errors.New("session resolve writer failure")
	if err := sessionResolveCommand(context.Background(), []string{"--token", reply.SessionToken}, errWriter{err: sessionResolveErr}, starter); !errors.Is(err, sessionResolveErr) {
		t.Fatalf("expected session resolve writer failure, got %v", err)
	}
	canceledClient, err := runtime.Dial(context.Background(), manager.SocketPath())
	if err != nil {
		t.Fatalf("dial canceled test client: %v", err)
	}
	defer canceledClient.Close()
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pingCommand(canceledCtx, io.Discard, fixedClientStarter{client: canceledClient}); err == nil {
		t.Fatal("expected ping rpc failure with canceled context")
	}
	if err := statusCommand(canceledCtx, io.Discard, fixedClientStarter{client: canceledClient}); err == nil {
		t.Fatal("expected status rpc failure with canceled context")
	}
	if err := sessionOpenCommand(canceledCtx, []string{"--project-root", projectRoot}, io.Discard, fixedClientStarter{client: canceledClient}); err == nil {
		t.Fatal("expected session open rpc failure with canceled context")
	}
	if err := sessionRevokeCommand(context.Background(), []string{"--bad"}, io.Discard, starter); err == nil {
		t.Fatal("expected session revoke parse error")
	}
	secondReply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:   "coverage-2",
		ProjectRoot: projectRoot,
		TTLSeconds:  int(runtime.DefaultSessionTTL.Seconds()),
	})
	if err != nil {
		t.Fatalf("open second session: %v", err)
	}
	sessionRevokeErr := errors.New("session revoke writer failure")
	if err := sessionRevokeCommand(context.Background(), []string{"--token", secondReply.SessionToken}, errWriter{err: sessionRevokeErr}, starter); !errors.Is(err, sessionRevokeErr) {
		t.Fatalf("expected session revoke writer failure, got %v", err)
	}
	if err := sessionRevokeCommand(context.Background(), []string{"--token", secondReply.SessionToken}, io.Discard, &fakeStarter{err: io.EOF}); err == nil {
		t.Fatal("expected session revoke ensureClient failure")
	}
	if err := sessionResolveCommand(context.Background(), []string{"--token", reply.SessionToken}, io.Discard, &fakeStarter{err: io.EOF}); err == nil {
		t.Fatal("expected session resolve ensureClient failure")
	}
	if err := tuiCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected tui parse error")
	}
	tuiErr := errors.New("tui writer failure")
	if err := tuiCommand(context.Background(), []string{"--project-root", projectRoot}, errWriter{err: tuiErr}); !errors.Is(err, tuiErr) {
		t.Fatalf("expected tui writer failure, got %v", err)
	}
	missingItemProject := t.TempDir()
	if err := projectBindCommand(context.Background(), []string{"--project-root", missingItemProject, "--hooks=false", "--alias", "secret_01=missing_item"}, io.Discard); err != nil {
		t.Fatalf("project bind missing-item project: %v", err)
	}
	if err := tuiCommand(context.Background(), []string{"--project-root", missingItemProject}, io.Discard); err == nil {
		t.Fatal("expected tui missing-item failure")
	}
	invalidBackupTarget := t.TempDir()
	if err := exportBackupCommand(context.Background(), []string{"--output", invalidBackupTarget, "--recovery-passphrase", "backup-passphrase"}, io.Discard); err == nil {
		t.Fatal("expected export backup path failure")
	}
	if err := restoreBackupCommand(context.Background(), []string{"--input", filepath.Join(t.TempDir(), "missing-backup.json"), "--recovery-passphrase", "backup-passphrase", "--master-password", "restored-password"}, io.Discard); err == nil {
		t.Fatal("expected restore backup missing-input failure")
	}
	t.Setenv("HASP_MASTER_PASSWORD", "wrong password")
	if err := exportBackupCommand(context.Background(), []string{"--output", filepath.Join(t.TempDir(), "backup.json"), "--recovery-passphrase", "backup-passphrase"}, io.Discard); err == nil {
		t.Fatal("expected export backup wrong-password failure")
	}
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
}

func TestStoreCreationFailureBranches(t *testing.T) {
	lockAppSeams(t)
	origNewStore := newVaultStoreFn
	defer func() { newVaultStoreFn = origNewStore }()
	newVaultStoreFn = func() (*store.Store, error) {
		return nil, errors.New("store init fail")
	}

	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("API_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	assertStoreFail := func(name string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "store init fail") {
			t.Fatalf("%s: expected store init fail, got %v", name, err)
		}
	}

	assertStoreFail("initCommand", initCommand(context.Background(), io.Discard))
	assertStoreFail("importCommand", importCommand(context.Background(), []string{envPath}, io.Discard))
	assertStoreFail("setCommand", setCommand(context.Background(), []string{"--name", "api_token", "--value", "abc123"}, io.Discard))
	assertStoreFail("redactCommand", redactCommand(context.Background(), bytes.NewBufferString("secret"), io.Discard))
	assertStoreFail("projectBindCommand", projectBindCommand(context.Background(), []string{"--project-root", t.TempDir(), "--hooks=false"}, io.Discard))
	assertStoreFail("projectStatusCommand", projectStatusCommand(context.Background(), []string{"--project-root", t.TempDir()}, io.Discard))
	assertStoreFail("projectUnbindCommand", projectUnbindCommand(context.Background(), []string{"--project-root", t.TempDir()}, io.Discard))
	if _, err := openVaultHandle(context.Background()); err == nil || !strings.Contains(err.Error(), "store init fail") {
		t.Fatalf("openVaultHandle: expected store init fail, got %v", err)
	}
	assertStoreFail("exportBackupCommand", exportBackupCommand(context.Background(), []string{"--output", filepath.Join(t.TempDir(), "backup.json"), "--recovery-passphrase", "backup-passphrase"}, io.Discard))
	assertStoreFail("restoreBackupCommand", restoreBackupCommand(context.Background(), []string{"--input", filepath.Join(t.TempDir(), "backup.json"), "--recovery-passphrase", "backup-passphrase", "--master-password", "restored-password"}, io.Discard))

	starter := newDaemonTestStarter(t)
	assertStoreFail("captureCommand", captureCommand(context.Background(), []string{"--name", "captured_secret", "--value", "top-secret", "--project-root", t.TempDir(), "--grant-project", "window", "--grant-write"}, io.Discard, starter))
}

func TestWrongPasswordAndBadPathBranches(t *testing.T) {
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("API_TOKEN=abc123\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	t.Setenv("HASP_MASTER_PASSWORD", "wrong-password")
	if err := importCommand(context.Background(), []string{envPath}, io.Discard); err == nil {
		t.Fatal("expected importCommand wrong-password failure")
	}
	if err := setCommand(context.Background(), []string{"--name", "api_token", "--value", "abc123"}, io.Discard); err == nil {
		t.Fatal("expected setCommand wrong-password failure")
	}
	if err := projectBindCommand(context.Background(), []string{"--project-root", projectRoot, "--hooks=false"}, io.Discard); err == nil {
		t.Fatal("expected projectBindCommand wrong-password failure")
	}
	if err := projectStatusCommand(context.Background(), []string{"--project-root", projectRoot}, io.Discard); err == nil {
		t.Fatal("expected projectStatusCommand wrong-password failure")
	}
	if err := projectUnbindCommand(context.Background(), []string{"--project-root", projectRoot}, io.Discard); err == nil {
		t.Fatal("expected projectUnbindCommand wrong-password failure")
	}
	if err := redactCommand(context.Background(), bytes.NewBufferString("secret"), io.Discard); err == nil {
		t.Fatal("expected redactCommand wrong-password failure")
	}

	starter := newDaemonTestStarter(t)
	if err := captureCommand(context.Background(), []string{"--name", "captured_secret", "--value", "top-secret", "--project-root", projectRoot, "--grant-project", "window", "--grant-write"}, io.Discard, starter); err == nil {
		t.Fatal("expected captureCommand wrong-password failure")
	}
	if err := tuiCommand(context.Background(), []string{"--project-root", projectRoot}, io.Discard); err == nil {
		t.Fatal("expected tuiCommand openVaultHandle failure")
	}
}

func TestOpenVaultHandleExplainsMissingPasswordAndUnavailableConvenienceUnlock(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	t.Setenv("HASP_MASTER_PASSWORD", "")
	if _, err := openVaultHandle(context.Background()); err == nil || !strings.Contains(err.Error(), "HASP_MASTER_PASSWORD is not set and convenience unlock is unavailable") {
		t.Fatalf("expected clearer convenience-unlock message, got %v", err)
	}
}

func enableConvenienceUnlockForAppTests(t *testing.T, homeDir string, password string) {
	t.Helper()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", password)
	keyring := newAppMemoryKeyring()
	origNewStore := newVaultStoreFn
	t.Cleanup(func() { newVaultStoreFn = origNewStore })
	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }

	vaultStore, err := store.New(keyring)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), password); err != nil && !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), password)
	if err != nil {
		t.Fatalf("open with password: %v", err)
	}
	if err := handle.EnableConvenienceUnlock(context.Background()); err != nil {
		t.Fatalf("enable convenience unlock: %v", err)
	}
}

type appMemoryKeyring struct {
	values map[string]string
}

func newAppMemoryKeyring() *appMemoryKeyring {
	return &appMemoryKeyring{values: map[string]string{}}
}

func (m *appMemoryKeyring) Set(_ context.Context, service string, account string, value string) error {
	m.values[service+"|"+account] = value
	return nil
}

func (m *appMemoryKeyring) Get(service string, account string) (string, error) {
	value, ok := m.values[service+"|"+account]
	if !ok {
		return "", store.ErrKeyringUnavailable
	}
	return value, nil
}

func (m *appMemoryKeyring) Delete(service string, account string) error {
	delete(m.values, service+"|"+account)
	return nil
}
