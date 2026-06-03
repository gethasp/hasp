package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
	"github.com/gethasp/hasp/apps/server/internal/telemetry"
)

type doctorIntegrationRPC struct {
	err   error
	reply runtime.IntegrationDoctorResponse
}

func (r *doctorIntegrationRPC) DoctorIntegration(req runtime.IntegrationDoctorRPCRequest, reply *runtime.IntegrationDoctorResponse) error {
	if r.err != nil {
		return r.err
	}
	if r.reply.TargetID == "" {
		r.reply.TargetID = req.TargetID
	}
	if r.reply.ProfileID == "" {
		r.reply.ProfileID = req.ProfileID
	}
	*reply = r.reply
	return nil
}

func startDoctorIntegrationRPC(t *testing.T, service *doctorIntegrationRPC) consumerCommandStarter {
	t.Helper()
	socketPath := shortSocketPath(t, "doctor-integration.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen doctor integration rpc: %v", err)
	}
	server := rpc.NewServer()
	if err := server.RegisterName("HASP", service); err != nil {
		t.Fatalf("register doctor integration rpc: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return consumerCommandStarter{socketPath: socketPath}
}

func TestCoverage100RemainingCommandBranches(t *testing.T) {
	lockAppSeams(t)

	if err := versionCommand(context.Background(), nil, errWriter{err: errors.New("version write fail")}); err == nil {
		t.Fatal("expected version writer failure")
	}
	var out bytes.Buffer
	if err := renderRepoCheckResult(&out, "/tmp/repo", nil, false, "vault unavailable"); err != nil {
		t.Fatalf("render repo warning: %v", err)
	}
	if !strings.Contains(out.String(), "matching was skipped") {
		t.Fatalf("expected warning lead, got %q", out.String())
	}
	projectRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectRoot, "README.md"), []byte("clean"), 0o600); err != nil {
		t.Fatalf("write clean project file: %v", err)
	}
	origOpenVault := openVaultHandleFn
	origCanonical := appCanonicalProjectRootFn
	t.Cleanup(func() {
		openVaultHandleFn = origOpenVault
		appCanonicalProjectRootFn = origCanonical
	})
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, store.ErrVaultNotInitialized }
	appCanonicalProjectRootFn = func(context.Context, string) (string, error) { return projectRoot, nil }
	checkDeps := defaultExecDeps()
	checkDeps.GitLsFiles = func(context.Context, string) ([]string, error) { return []string{"README.md"}, nil }
	var stderr bytes.Buffer
	if err := checkRepoCommandWithDeps(context.Background(), []string{"--project-root", projectRoot}, io.Discard, &stderr, checkDeps); err != nil {
		t.Fatalf("check repo vault warning: %v", err)
	}
	if !strings.Contains(stderr.String(), "managed-value matching was skipped") {
		t.Fatalf("expected vault warning on stderr, got %q", stderr.String())
	}
	hugePath := filepath.Join(projectRoot, "huge.bin")
	if err := os.WriteFile(hugePath, make([]byte, 4<<20+1), 0o600); err != nil {
		t.Fatalf("write oversized repo file: %v", err)
	}
	checkDeps.GitLsFiles = func(context.Context, string) ([]string, error) { return []string{"huge.bin"}, nil }
	var strictOut bytes.Buffer
	if err := checkRepoCommandWithDeps(context.Background(), []string{"--project-root", projectRoot, "--fail-on-skipped"}, &strictOut, io.Discard, checkDeps); err == nil || !strings.Contains(err.Error(), "skipped") {
		t.Fatalf("expected strict skipped-file failure, got %v output=%q", err, strictOut.String())
	}
	openVaultHandleFn = origOpenVault
	appCanonicalProjectRootFn = origCanonical
	if err := policySetCommand(context.Background(), []string{"--file", filepath.Join(t.TempDir(), "missing.json")}, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected policy set read failure")
	}
	if err := policyValidateCommand(context.Background(), []string{"--file", filepath.Join(t.TempDir(), "missing.json")}, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected policy validate read failure")
	}
	if err := removeAgentConsumerConfig(setupAgentSpec{Format: "manual"}, "unused"); err != nil {
		t.Fatalf("manual agent config removal should be a no-op: %v", err)
	}
	if confirmTelemetry(nil, io.Discard) {
		t.Fatal("nil telemetry stdin should decline")
	}
	revokeService := &consumerCommandRPC{revokeReply: runtime.RevokeLeaseResponse{Revoked: true, RevokedCount: 1}}
	revokeStarter := startConsumerCommandRPC(t, revokeService)
	out.Reset()
	if err := leaseRevokeCommand(context.Background(), []string{"lease-1"}, &out, revokeStarter); err != nil {
		t.Fatalf("lease revoke human success: %v", err)
	}
	if !strings.Contains(out.String(), "Revoked lease lease-1") {
		t.Fatalf("lease revoke output = %q", out.String())
	}

	opts := setupOptions{Telemetry: setupOptionalBool{set: true, value: true}}
	if err := setupResolveTelemetryOption(&opts, newSetupPrompter(strings.NewReader(""), io.Discard)); err != nil {
		t.Fatalf("pre-set telemetry option: %v", err)
	}
	opts = setupOptions{}
	if err := setupResolveTelemetryOption(&opts, newSetupPrompter(strings.NewReader(""), errWriter{err: errors.New("stage write fail")})); err == nil {
		t.Fatal("expected telemetry stage writer failure")
	}
	opts = setupOptions{}
	if err := setupResolveTelemetryOption(&opts, newSetupPrompter(errReader{err: errors.New("prompt read fail")}, io.Discard)); err == nil {
		t.Fatal("expected telemetry prompt failure")
	}
	if err := setupConvenienceUnlockRequiredError(""); err == nil || !strings.Contains(err.Error(), "required but is unavailable") {
		t.Fatalf("expected blank convenience detail error, got %v", err)
	}

	service := &doctorIntegrationRPC{reply: runtime.IntegrationDoctorResponse{
		OK:           true,
		RuntimeProbe: true,
		DurationMS:   7,
		Checks:       []runtime.IntegrationDoctorCheck{{Name: "binary", OK: true, Message: "ok", FixHint: "none"}},
	}}
	starter := startDoctorIntegrationRPC(t, service)
	if err := doctorIntegrationCommand(context.Background(), "codex", "default", false, io.Discard, consumerCommandStarter{ensureErr: errors.New("ensure fail")}); err == nil {
		t.Fatal("expected doctor integration ensure failure")
	}
	service.err = errors.New("doctor rpc fail")
	if err := doctorIntegrationCommand(context.Background(), "codex", "default", false, io.Discard, starter); err == nil {
		t.Fatal("expected doctor integration rpc failure")
	}
	service.err = nil
	if err := doctorIntegrationCommand(context.Background(), "codex", "default", false, io.Discard, starter); err != nil {
		t.Fatalf("doctor integration human success: %v", err)
	}

	runtimeDeps := defaultRuntimeDeps()
	client := runtimeDeps.ConnectIfRunning(context.Background(), starter)
	if client == nil {
		t.Fatal("expected ConnectIfRunning to return a live client")
	}
	_ = client.Close()
}

func TestCoverage100AuditExportAndVerifyBranches(t *testing.T) {
	lockAppSeams(t)

	origNewAuditLog := newAuditLogFn
	origAuditEvents := auditEventsFn
	origOpenVault := openVaultHandleFn
	t.Cleanup(func() {
		newAuditLogFn = origNewAuditLog
		auditEventsFn = origAuditEvents
		openVaultHandleFn = origOpenVault
		clearAuditHMACKey()
	})

	for _, args := range [][]string{
		{"--bad"},
		{"extra"},
		{"--format", "json"},
		{"--from", "not-time"},
		{"--to", "not-time"},
		{"--from", "2026-05-14T02:00:00Z", "--to", "2026-05-14T01:00:00Z"},
	} {
		if err := auditExportCommand(context.Background(), args, io.Discard); err == nil {
			t.Fatalf("audit export %v should fail", args)
		}
	}

	newAuditLogFn = func() (*audit.Log, error) { return nil, errors.New("audit open fail") }
	if err := auditExportCommand(context.Background(), nil, io.Discard); err == nil {
		t.Fatal("expected audit export log open failure")
	}

	newAuditLogFn = func() (*audit.Log, error) {
		return audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(t.TempDir(), "audit.jsonl")}), nil
	}
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return nil, errors.New("events fail") }
	if err := auditExportCommand(context.Background(), nil, io.Discard); err == nil {
		t.Fatal("expected audit export events failure")
	}

	t.Setenv("HASP_HOME", t.TempDir())
	vaultStore, err := store.New(store.NewDefaultKeyring())
	if err != nil {
		t.Fatalf("store new: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("store init: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit-export.jsonl")
	newAuditLogFn = func() (*audit.Log, error) {
		return audit.NewForPaths(paths.Paths{AuditPath: auditPath}), nil
	}
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return handle, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) {
		return []audit.Event{{Sequence: 1, Timestamp: time.Date(2026, 5, 14, 1, 0, 0, 0, time.UTC), Type: audit.EventRead}}, nil
	}
	out := bytes.Buffer{}
	setAuditHMACKey(bytes.Repeat([]byte{7}, 32))
	if err := auditExportCommand(context.Background(), []string{"--from", "2026-05-14T00:00:00Z", "--to", "2026-05-14T02:00:00Z"}, io.Discard); err != nil {
		t.Fatalf("audit export with cached key: %v", err)
	}
	clearAuditHMACKey()
	if err := auditExportCommand(context.Background(), []string{"--from", "2026-05-14T00:00:00Z", "--to", "2026-05-14T02:00:00Z"}, &out); err != nil {
		t.Fatalf("audit export with vault key: %v", err)
	}
	if !strings.Contains(out.String(), `"_trailer":true`) {
		t.Fatalf("expected export trailer, got %q", out.String())
	}

	newAuditLogFn = func() (*audit.Log, error) {
		return audit.NewForPaths(paths.Paths{AuditPath: t.TempDir()}), nil
	}
	if err := auditCommandWithArgs(context.Background(), []string{"--verify"}, io.Discard); err == nil {
		t.Fatal("expected audit verify read failure")
	}

	corruptPath := filepath.Join(t.TempDir(), "audit-corrupt.jsonl")
	corruptLog := audit.NewForPaths(paths.Paths{AuditPath: corruptPath})
	if _, err := corruptLog.Append(audit.EventRun, "tester", nil); err != nil {
		t.Fatalf("append audit event: %v", err)
	}
	if err := os.WriteFile(corruptPath, []byte("{not-json}\n"), 0o600); err != nil {
		t.Fatalf("corrupt audit log: %v", err)
	}
	newAuditLogFn = func() (*audit.Log, error) { return corruptLog, nil }
	if err := auditCommandWithArgs(context.Background(), []string{"--verify"}, io.Discard); err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("expected corrupt audit verification error, got %v", err)
	}
	if err := auditCommandWithArgs(context.Background(), []string{"--verify"}, errWriter{err: errors.New("verify render fail")}); err == nil {
		t.Fatal("expected audit verify render failure")
	}

	key := bytes.Repeat([]byte{9}, 32)
	untrustedPath := filepath.Join(t.TempDir(), "audit-untrusted.jsonl")
	untrustedLog := audit.NewForPaths(paths.Paths{AuditPath: untrustedPath})
	if _, err := untrustedLog.Append(audit.EventInit, "user", nil); err != nil {
		t.Fatalf("append legacy audit event: %v", err)
	}
	if _, err := untrustedLog.WithKey(key).Append(audit.EventImport, "user", nil); err != nil {
		t.Fatalf("append keyed audit event: %v", err)
	}
	if _, err := untrustedLog.WithKey(nil).Append(audit.EventRead, "user", nil); err != nil {
		t.Fatalf("append untrusted audit event: %v", err)
	}
	newAuditLogFn = func() (*audit.Log, error) { return untrustedLog, nil }
	setAuditHMACKey(key)
	var verifyJSON bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{"--verify", "--json"}, &verifyJSON); err != nil {
		t.Fatalf("audit verify json with unauthenticated entries: %v", err)
	}
	if !strings.Contains(verifyJSON.String(), `"unauthenticated_after_keyed":1`) {
		t.Fatalf("expected unauthenticated JSON field, got %q", verifyJSON.String())
	}
	var verifyHuman bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{"--verify"}, &verifyHuman); err != nil {
		t.Fatalf("audit verify human with unauthenticated entries: %v", err)
	}
	if !strings.Contains(verifyHuman.String(), "Unauthenticated entries") {
		t.Fatalf("expected unauthenticated human field, got %q", verifyHuman.String())
	}
}

func TestCoverage100TelemetryRemainingBranches(t *testing.T) {
	t.Setenv("HASP_TELEMETRY_TEST_STATE", "")
	if err := telemetryStatusCommand(context.Background(), nil, io.Discard, false); err == nil {
		t.Fatal("expected telemetry status load failure without explicit test state")
	}

	path := withAppTelemetryState(t)
	telemetry.Endpoint = telemetry.TrustedEndpoint
	if _, err := telemetry.DefaultStore().Enable(time.Now().UTC()); err != nil {
		t.Fatalf("enable telemetry: %v", err)
	}
	state, err := telemetry.DefaultStore().Load()
	if err != nil {
		t.Fatalf("load telemetry: %v", err)
	}
	state.LastPingAt = time.Date(2026, 5, 14, 3, 0, 0, 0, time.UTC)
	if err := telemetry.DefaultStore().Save(state); err != nil {
		t.Fatalf("save telemetry: %v", err)
	}
	telemetry.Endpoint = ""
	disabledEndpointStatus, err := telemetryStatus(false)
	if err != nil {
		t.Fatalf("telemetry status with unconfigured endpoint: %v", err)
	}
	if disabledEndpointStatus.Reason != "telemetry endpoint is not configured" {
		t.Fatalf("endpoint status reason = %q", disabledEndpointStatus.Reason)
	}
	telemetry.Endpoint = telemetry.TrustedEndpoint
	t.Setenv("HASP_VERSION", "bad version with spaces")
	if err := telemetryStatusCommand(context.Background(), nil, io.Discard, true); err == nil {
		t.Fatal("expected telemetry preview encode failure")
	}
	t.Setenv("HASP_VERSION", "")
	if err := telemetryStatusCommand(context.Background(), nil, errWriter{err: errors.New("preview write fail")}, true); err == nil {
		t.Fatal("expected telemetry preview payload writer failure")
	}
	if err := telemetryStatusCommand(context.Background(), nil, &failAfterWriter{remaining: 1}, false); err == nil {
		t.Fatal("expected telemetry endpoint writer failure")
	}
	if err := telemetryStatusCommand(context.Background(), nil, &failAfterWriter{remaining: 2}, false); err == nil {
		t.Fatal("expected telemetry hash writer failure")
	}
	if err := telemetryStatusCommand(context.Background(), nil, &failAfterWriter{remaining: 3}, false); err == nil {
		t.Fatal("expected telemetry last-ping writer failure")
	}

	state.InstallID = ""
	state.InstallYear = 0
	if err := telemetry.DefaultStore().Save(state); err != nil {
		t.Fatalf("save missing install id: %v", err)
	}
	status, err := telemetryStatus(true)
	if err != nil {
		t.Fatalf("telemetry preview with install-id update: %v", err)
	}
	if status.Payload == nil {
		t.Fatal("expected telemetry preview payload")
	}
	if saved, err := telemetry.DefaultStore().Load(); err != nil || saved.InstallID == "" || saved.InstallYear == 0 {
		t.Fatalf("expected updated install id to be persisted, saved=%+v err=%v", saved, err)
	}

	dirPath := filepath.Join(t.TempDir(), "telemetry-dir")
	if err := os.Mkdir(dirPath, 0o700); err != nil {
		t.Fatalf("mkdir telemetry dir: %v", err)
	}
	t.Setenv("HASP_TELEMETRY_TEST_STATE", dirPath)
	if err := telemetryEnableCommand(context.Background(), []string{"--yes"}, strings.NewReader(""), io.Discard); err == nil {
		t.Fatal("expected telemetry enable store failure")
	}
	if err := telemetryDisableCommand(context.Background(), nil, io.Discard); err == nil {
		t.Fatal("expected telemetry disable store failure")
	}
	if err := telemetryForgetCommand(context.Background(), nil, io.Discard, io.Discard); err == nil {
		t.Fatal("expected telemetry forget store failure")
	}

	t.Setenv("HASP_TELEMETRY_TEST_STATE", path)
	if !confirmTelemetry(strings.NewReader("yes\n"), nil) {
		t.Fatal("expected telemetry confirmation without stdout to accept yes")
	}
}

func TestCoverage100RunSetupRemainingBranches(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HOME", homeDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(homeDir, ".config"))
	t.Setenv("SETUP_PW", "correct horse battery staple")

	origNewStore := newVaultStoreFn
	origHome := setupUserHomeDirFn
	origLookPath := setupLookPathFn
	origWriteIntro := setupWriteIntroFn
	origWriteSelected := setupWriteSelectedAgentsFn
	origWriteAgents := setupWriteAgentConfigsFn
	origStoreUpsert := storeUpsertAgentFn
	origVerifyHarness := setupVerifyHarnessFn
	origVerifyProof := setupVerifyBrokeredProofFn
	origEnableConvenience := setupEnableConvenienceUnlockFn
	origVerifyConvenience := setupVerifyConvenienceUnlockFn
	t.Cleanup(func() {
		newVaultStoreFn = origNewStore
		setupUserHomeDirFn = origHome
		setupLookPathFn = origLookPath
		setupWriteIntroFn = origWriteIntro
		setupWriteSelectedAgentsFn = origWriteSelected
		setupWriteAgentConfigsFn = origWriteAgents
		storeUpsertAgentFn = origStoreUpsert
		setupVerifyHarnessFn = origVerifyHarness
		setupVerifyBrokeredProofFn = origVerifyProof
		setupEnableConvenienceUnlockFn = origEnableConvenience
		setupVerifyConvenienceUnlockFn = origVerifyConvenience
	})

	keyring := &memorySetupKeyring{}
	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }
	setupUserHomeDirFn = func() (string, error) { return homeDir, nil }
	setupLookPathFn = func(string) (string, error) { return "/usr/bin/codex", nil }
	setupVerifyHarnessFn = func(context.Context, []setupAgentSpec) (map[string]any, error) { return map[string]any{}, nil }
	setupVerifyBrokeredProofFn = func(context.Context, string, []store.VisibleReference) (map[string]any, error) {
		return map[string]any{"performed": false, "ready": false}, nil
	}

	base := setupOptions{
		NonInteractive:          true,
		HaspHome:                filepath.Join(homeDir, ".hasp"),
		Repo:                    projectRoot,
		Agents:                  setupAgentFlags{"codex-cli"},
		PasswordEnv:             "SETUP_PW",
		DefaultPolicy:           store.PolicySession,
		InstallHooks:            setupOptionalBool{set: true, value: false},
		EnableConvenienceUnlock: setupOptionalBool{set: true, value: false},
		OverwriteExistingConfig: setupOptionalBool{set: true, value: true},
		Telemetry:               setupOptionalBool{set: true, value: true},
	}

	setupWriteAgentConfigsFn = func([]setupAgentSpec, string) ([]setupAgentOutcome, error) {
		return []setupAgentOutcome{{ID: "codex-cli", ConfigPath: "/tmp/codex.json"}}, nil
	}
	storeUpsertAgentFn = func(*store.Handle, store.AgentConsumer) (store.AgentConsumer, error) {
		return store.AgentConsumer{}, errors.New("upsert from setup fail")
	}
	if _, err := runSetup(context.Background(), base, bytes.NewReader(nil), io.Discard); err == nil {
		t.Fatal("expected setup agent upsert failure")
	}

	storeUpsertAgentFn = func(_ *store.Handle, consumer store.AgentConsumer) (store.AgentConsumer, error) {
		return consumer, nil
	}
	t.Setenv(telemetry.EnvDisabled, "1")
	summary, err := runSetup(context.Background(), base, bytes.NewReader(nil), io.Discard)
	if err != nil {
		t.Fatalf("runSetup with telemetry disabled by env: %v", err)
	}
	if summary.Telemetry != "blocked_by_env" {
		t.Fatalf("telemetry state = %q, want blocked_by_env", summary.Telemetry)
	}

	t.Setenv(telemetry.EnvDisabled, "")
	t.Setenv("HASP_TELEMETRY_TEST_STATE", t.TempDir())
	base.HaspHome = filepath.Join(homeDir, ".hasp-telemetry-error")
	if _, err := runSetup(context.Background(), base, bytes.NewReader(nil), io.Discard); err == nil {
		t.Fatal("expected runSetup telemetry enable failure")
	}

	t.Setenv("HASP_TELEMETRY_TEST_STATE", filepath.Join(t.TempDir(), "telemetry.json"))
	base.HaspHome = filepath.Join(homeDir, ".hasp-enabled")
	summary, err = runSetup(context.Background(), base, bytes.NewReader(nil), io.Discard)
	if err != nil {
		t.Fatalf("runSetup with telemetry enabled: %v", err)
	}
	if summary.Telemetry != "enabled" {
		t.Fatalf("telemetry state = %q, want enabled", summary.Telemetry)
	}

	setupWriteIntroFn = func(io.Writer) error { return nil }
	setupWriteSelectedAgentsFn = func(io.Writer, []setupAgentSpec) error { return nil }
	interactive := base
	interactive.NonInteractive = false
	interactive.HaspHome = filepath.Join(homeDir, ".hasp-interactive")
	interactive.AutoProtectRepos = setupOptionalBool{set: true, value: false}
	interactive.Telemetry = setupOptionalBool{}
	interactive.ImportPath = filepath.Join(t.TempDir(), "skip-before-prepare.env")
	interactive.BindImports = true
	if _, err := runSetup(context.Background(), interactive, bytes.NewReader(nil), errWriter{err: errors.New("telemetry stage fail")}); err == nil {
		t.Fatal("expected runSetup telemetry resolution failure")
	} else if !strings.Contains(err.Error(), "telemetry stage fail") {
		t.Fatalf("expected telemetry stage failure, got %v", err)
	}
	if _, err := runSetup(context.Background(), interactive, errReader{err: errors.New("telemetry prompt fail")}, io.Discard); err == nil {
		t.Fatal("expected runSetup telemetry resolution failure")
	} else if !strings.Contains(err.Error(), "telemetry prompt fail") {
		t.Fatalf("expected telemetry prompt failure, got %v", err)
	}

	t.Setenv("HASP_TELEMETRY_TEST_STATE", filepath.Join(t.TempDir(), "telemetry-required.json"))
	requiredConvenience := base
	requiredConvenience.HaspHome = filepath.Join(homeDir, ".hasp-required-convenience")
	requiredConvenience.EnableConvenienceUnlock = setupOptionalBool{set: true, value: true, source: "always"}
	setupEnableConvenienceUnlockFn = func(context.Context, *store.Handle) error { return nil }
	setupVerifyConvenienceUnlockFn = func(context.Context, *store.Store) error { return store.ErrKeyringUnavailable }
	if _, err := runSetup(context.Background(), requiredConvenience, bytes.NewReader(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "convenience unlock was required") {
		t.Fatalf("expected required convenience unlock failure, got %v", err)
	}
}
