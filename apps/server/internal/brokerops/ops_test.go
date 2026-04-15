package brokerops

import (
	"context"
	"errors"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var fakeSessionProjectRoot string

func TestAuthorizeReferenceRetriesProjectAndSecretGrant(t *testing.T) {
	handle := newBrokeropsHandle(t)
	item, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("secret-value"), store.ItemMetadata{Policy: store.PolicySession})
	if err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	projectRoot := t.TempDir()
	binding, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": item.Name}, store.PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	resolved, err := AuthorizeReference(
		context.Background(),
		handle,
		binding.ID,
		projectRoot,
		"session-token",
		"secret_01",
		store.OperationRun,
		store.GrantWindow,
		store.GrantSession,
		"",
		time.Minute,
		"",
	)
	if err != nil {
		t.Fatalf("authorize reference: %v", err)
	}
	if resolved.Name != item.Name {
		t.Fatalf("resolved item = %q, want %q", resolved.Name, item.Name)
	}
}

func TestAuthorizeReferenceFailsClosedWithoutProjectGrant(t *testing.T) {
	handle := newBrokeropsHandle(t)
	item, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("secret-value"), store.ItemMetadata{Policy: store.PolicySession})
	if err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	projectRoot := t.TempDir()
	binding, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": item.Name}, store.PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	_, err = AuthorizeReference(
		context.Background(),
		handle,
		binding.ID,
		projectRoot,
		"session-token",
		"secret_01",
		store.OperationRun,
		"",
		"",
		"",
		time.Minute,
		"",
	)
	if err == nil || !strings.Contains(err.Error(), "project lease required") {
		t.Fatalf("expected fail-closed project lease error, got %v", err)
	}
}

func TestAuthorizeCaptureRequiresExplicitWriteGrant(t *testing.T) {
	handle := newBrokeropsHandle(t)
	projectRoot := t.TempDir()
	binding, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{}, store.PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	err = AuthorizeCapture(context.Background(), handle, binding.ID, "session-token", "generated_token", store.GrantWindow, "", time.Minute, false)
	if err == nil || !strings.Contains(err.Error(), "capture write grant required") {
		t.Fatalf("expected explicit write-grant error, got %v", err)
	}
}

func TestEnsureSessionProvidedAndAutoOpen(t *testing.T) {
	projectRoot := filepath.Join(t.TempDir(), "project")
	socketPath := filepath.Join("/tmp", "hasp-brokerops.sock")
	fakeSessionProjectRoot = projectRoot
	startBrokeropsRPCServer(t, socketPath)
	connector := fakeConnector{socketPath: socketPath}

	session, err := EnsureSession(context.Background(), connector, projectRoot, "existing-token", "brokerops-test")
	if err != nil {
		t.Fatalf("ensure provided session: %v", err)
	}
	if session.Token != "existing-token" || session.Info.ProjectRoot != projectRoot {
		t.Fatalf("unexpected provided session: %+v", session)
	}

	autoSession, err := EnsureSession(context.Background(), connector, projectRoot, "", "brokerops-test")
	if err != nil {
		t.Fatalf("ensure auto-open session: %v", err)
	}
	if autoSession.Token == "" || autoSession.Info.ProjectRoot != projectRoot {
		t.Fatalf("unexpected auto-open session: %+v", autoSession)
	}
}

func TestManagerConnectorEnsureAndConnect(t *testing.T) {
	home := t.TempDir()
	socket := filepath.Join("/tmp", "hasp-brokerops-manager.sock")
	t.Setenv(paths.EnvHome, home)
	t.Setenv(paths.EnvSocket, socket)
	t.Cleanup(func() {
		_ = os.Remove(socket)
	})

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
			t.Fatal("timed out waiting for brokerops daemon shutdown")
		}
	})

	connector := managerConnector{manager: manager}
	if err := connector.EnsureDaemon(context.Background()); err != nil {
		t.Fatalf("ensure daemon: %v", err)
	}
	client, err := connector.Connect(context.Background())
	if err != nil {
		t.Fatalf("connect daemon: %v", err)
	}
	defer client.Close()
	if _, err := client.Ping(context.Background()); err != nil {
		t.Fatalf("ping daemon: %v", err)
	}
}

func TestAuthorizeItemProjectLeaseThenSecretGrant(t *testing.T) {
	handle := newBrokeropsHandle(t)
	item, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("secret-value"), store.ItemMetadata{Policy: store.PolicySession})
	if err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{"secret_01": item.Name}, store.PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	resolved, err := AuthorizeItem(handle, binding.ID, "session-token", item, store.OperationRun, store.GrantWindow, store.GrantSession, time.Minute)
	if err != nil {
		t.Fatalf("authorize item: %v", err)
	}
	if resolved.Name != item.Name {
		t.Fatalf("resolved item = %q, want %q", resolved.Name, item.Name)
	}
}

func TestAuthorizeItemFailsWithoutGrants(t *testing.T) {
	handle := newBrokeropsHandle(t)
	item, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("secret-value"), store.ItemMetadata{Policy: store.PolicySession})
	if err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{"secret_01": item.Name}, store.PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := AuthorizeItem(handle, binding.ID, "session-token", item, store.OperationRun, "", "", time.Minute); err == nil || !strings.Contains(err.Error(), "project lease required") {
		t.Fatalf("expected fail-closed project lease error, got %v", err)
	}
}

func TestEnsureSessionConnectorFailures(t *testing.T) {
	connector := fakeFailConnector{err: errors.New("boom")}
	if _, err := EnsureSession(context.Background(), connector, t.TempDir(), "", "brokerops-test"); err == nil {
		t.Fatal("expected ensure session failure")
	}
}

func TestEnsureSessionRejectsProjectRootMismatch(t *testing.T) {
	projectRoot := filepath.Join(t.TempDir(), "project")
	socketPath := filepath.Join("/tmp", "hasp-brokerops-mismatch.sock")
	fakeSessionProjectRoot = filepath.Join(projectRoot, "other")
	startBrokeropsRPCServer(t, socketPath)
	connector := fakeConnector{socketPath: socketPath}

	if _, err := EnsureSession(context.Background(), connector, projectRoot, "existing-token", "brokerops-test"); err == nil || !strings.Contains(err.Error(), "project root mismatch") {
		t.Fatalf("expected project root mismatch, got %v", err)
	}
}

func TestAuthorizeItemUnknownPolicyPath(t *testing.T) {
	handle := newBrokeropsHandle(t)
	item, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("secret-value"), store.ItemMetadata{Policy: store.PolicySession})
	if err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), t.TempDir(), map[string]string{"secret_01": item.Name}, store.PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", store.GrantWindow, time.Minute); err != nil {
		t.Fatalf("grant lease: %v", err)
	}
	item.Metadata.Policy = store.SecretPolicy("bogus")
	if _, err := AuthorizeItem(handle, binding.ID, "session-token", item, store.OperationRun, "", "", time.Minute); err == nil || !strings.Contains(err.Error(), "unsupported approval path") {
		t.Fatalf("expected unknown policy error, got %v", err)
	}
}

func TestAuthorizeReferenceRequiresConvenienceGrantForWriteEnv(t *testing.T) {
	handle := newBrokeropsHandle(t)
	item, err := handle.UpsertItem("db_url", store.ItemKindKV, []byte("postgres://localhost"), store.ItemMetadata{Policy: store.PolicySession})
	if err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	projectRoot := t.TempDir()
	binding, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": item.Name}, store.PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	_, err = AuthorizeReference(
		context.Background(),
		handle,
		binding.ID,
		projectRoot,
		"session-token",
		"secret_01",
		store.OperationWriteEnv,
		store.GrantWindow,
		store.GrantSession,
		"",
		time.Minute,
		filepath.Join(projectRoot, ".env.local"),
	)
	if err == nil || !strings.Contains(err.Error(), "convenience approval required") {
		t.Fatalf("expected convenience approval error, got %v", err)
	}
}

func TestEnsureSessionWithManagerPropagatesManagerCreationFailure(t *testing.T) {
	lockBrokeropsSeams(t)
	origNewManager := newManagerFn
	defer func() { newManagerFn = origNewManager }()
	newManagerFn = func() (*runtime.Manager, error) { return nil, errors.New("manager fail") }
	if _, err := EnsureSessionWithManager(context.Background(), t.TempDir(), "", "brokerops-test"); err == nil || !strings.Contains(err.Error(), "manager fail") {
		t.Fatalf("expected manager creation failure, got %v", err)
	}
}

func TestAuthorizeReferenceSeamDrivenErrorPaths(t *testing.T) {
	lockBrokeropsSeams(t)
	handle := newBrokeropsHandle(t)
	item := store.Item{Name: "api_token", Metadata: store.ItemMetadata{Policy: store.PolicySession}}
	origResolve := resolveReferenceFn
	origGet := getItemFn
	origAuthorize := authorizeFn
	origGrantProject := grantProjectLeaseFn
	origGrantSecret := grantSecretUseFn
	origGrantConvenience := grantConvenienceFn
	defer func() {
		resolveReferenceFn = origResolve
		getItemFn = origGet
		authorizeFn = origAuthorize
		grantProjectLeaseFn = origGrantProject
		grantSecretUseFn = origGrantSecret
		grantConvenienceFn = origGrantConvenience
	}()

	resolveReferenceFn = func(*store.Handle, context.Context, string, string) (store.ResolvedReference, error) {
		return store.ResolvedReference{}, errors.New("resolve fail")
	}
	if _, err := AuthorizeReference(context.Background(), handle, "binding", t.TempDir(), "token", "secret_01", store.OperationRun, "", "", "", time.Minute, ""); err == nil || !strings.Contains(err.Error(), "resolve fail") {
		t.Fatalf("expected resolve failure, got %v", err)
	}

	resolveReferenceFn = func(*store.Handle, context.Context, string, string) (store.ResolvedReference, error) {
		return store.ResolvedReference{ItemName: "api_token"}, nil
	}
	getItemFn = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("get fail") }
	if _, err := AuthorizeReference(context.Background(), handle, "binding", t.TempDir(), "token", "secret_01", store.OperationRun, "", "", "", time.Minute, ""); err == nil || !strings.Contains(err.Error(), "get fail") {
		t.Fatalf("expected get failure, got %v", err)
	}

	getItemFn = func(*store.Handle, string) (store.Item, error) { return item, nil }
	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		return store.AccessDecision{Reason: "denied"}
	}
	if _, err := AuthorizeReference(context.Background(), handle, "binding", t.TempDir(), "token", "secret_01", store.OperationRun, "", "", "", time.Minute, ""); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("expected access denied error, got %v", err)
	}

	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		return store.AccessDecision{RequiresPrompt: true, Reason: "project_lease_required"}
	}
	grantProjectLeaseFn = func(*store.Handle, string, string, store.GrantScope, time.Duration) (store.ProjectLease, error) {
		return store.ProjectLease{}, errors.New("grant project fail")
	}
	if _, err := AuthorizeReference(context.Background(), handle, "binding", t.TempDir(), "token", "secret_01", store.OperationRun, store.GrantWindow, "", "", time.Minute, ""); err == nil || !strings.Contains(err.Error(), "grant project fail") {
		t.Fatalf("expected grant project failure, got %v", err)
	}

	callCount := 0
	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		callCount++
		if callCount == 1 {
			return store.AccessDecision{RequiresPrompt: true, Reason: "project_and_convenience_approval_required"}
		}
		return store.AccessDecision{RequiresPrompt: true, Reason: "convenience_approval_required"}
	}
	grantProjectLeaseFn = func(*store.Handle, string, string, store.GrantScope, time.Duration) (store.ProjectLease, error) {
		return store.ProjectLease{}, nil
	}
	grantConvenienceFn = func(*store.Handle, string, string, string, []string, string, store.GrantScope, time.Duration) (store.ConvenienceGrant, error) {
		return store.ConvenienceGrant{}, errors.New("grant convenience fail")
	}
	if _, err := AuthorizeReference(context.Background(), handle, "binding", t.TempDir(), "token", "secret_01", store.OperationWriteEnv, store.GrantWindow, "", store.GrantWindow, time.Minute, "/tmp/.env"); err == nil || !strings.Contains(err.Error(), "grant convenience fail") {
		t.Fatalf("expected convenience grant failure, got %v", err)
	}

	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		return store.AccessDecision{RequiresPrompt: true, Reason: "project_lease_required"}
	}
	if _, err := AuthorizeReference(context.Background(), handle, "binding", t.TempDir(), "token", "secret_01", store.OperationRun, store.GrantWindow, "", "", time.Minute, ""); err == nil || !strings.Contains(err.Error(), "approval still required after retry") {
		t.Fatalf("expected retry exhaustion, got %v", err)
	}
}

func TestAuthorizeItemSeamDrivenErrorPaths(t *testing.T) {
	lockBrokeropsSeams(t)
	handle := newBrokeropsHandle(t)
	item := store.Item{Name: "api_token", Metadata: store.ItemMetadata{Policy: store.PolicySession}}
	origAuthorize := authorizeFn
	origGrantProject := grantProjectLeaseFn
	origGrantSecret := grantSecretUseFn
	defer func() {
		authorizeFn = origAuthorize
		grantProjectLeaseFn = origGrantProject
		grantSecretUseFn = origGrantSecret
	}()

	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		return store.AccessDecision{Reason: "denied"}
	}
	if _, err := AuthorizeItem(handle, "binding", "token", item, store.OperationRun, "", "", time.Minute); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("expected access denied error, got %v", err)
	}

	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		return store.AccessDecision{RequiresPrompt: true, Reason: "project_lease_required"}
	}
	grantProjectLeaseFn = func(*store.Handle, string, string, store.GrantScope, time.Duration) (store.ProjectLease, error) {
		return store.ProjectLease{}, errors.New("grant project fail")
	}
	if _, err := AuthorizeItem(handle, "binding", "token", item, store.OperationRun, store.GrantWindow, "", time.Minute); err == nil || !strings.Contains(err.Error(), "grant project fail") {
		t.Fatalf("expected project grant failure, got %v", err)
	}

	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		return store.AccessDecision{RequiresPrompt: true, Reason: "access_secret_prompt_required"}
	}
	grantProjectLeaseFn = origGrantProject
	grantSecretUseFn = func(*store.Handle, string, string, string, store.GrantScope, time.Duration, bool) (store.SecretGrant, error) {
		return store.SecretGrant{}, errors.New("grant secret fail")
	}
	item.Metadata.Policy = store.PolicyAccess
	if _, err := AuthorizeItem(handle, "binding", "token", item, store.OperationRun, "", store.GrantWindow, time.Minute); err == nil || !strings.Contains(err.Error(), "grant secret fail") {
		t.Fatalf("expected secret grant failure, got %v", err)
	}

	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		return store.AccessDecision{RequiresPrompt: true, Reason: "project_lease_required"}
	}
	grantSecretUseFn = origGrantSecret
	grantProjectLeaseFn = func(*store.Handle, string, string, store.GrantScope, time.Duration) (store.ProjectLease, error) {
		return store.ProjectLease{}, nil
	}
	if _, err := AuthorizeItem(handle, "binding", "token", item, store.OperationRun, store.GrantWindow, "", time.Minute); err == nil || !strings.Contains(err.Error(), "approval still required after retry") {
		t.Fatalf("expected retry exhaustion, got %v", err)
	}
}

func TestAuthorizeCaptureSeamDrivenErrorPaths(t *testing.T) {
	lockBrokeropsSeams(t)
	handle := newBrokeropsHandle(t)
	origGet := getItemFn
	origAuthorize := authorizeFn
	origGrantProject := grantProjectLeaseFn
	defer func() {
		getItemFn = origGet
		authorizeFn = origAuthorize
		grantProjectLeaseFn = origGrantProject
	}()

	getItemFn = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("get fail") }
	if err := AuthorizeCapture(context.Background(), handle, "binding", "token", "item", "", "", time.Minute, false); err == nil || !strings.Contains(err.Error(), "get fail") {
		t.Fatalf("expected get failure, got %v", err)
	}

	getItemFn = func(*store.Handle, string) (store.Item, error) { return store.Item{}, store.ErrItemNotFound }
	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		return store.AccessDecision{Allowed: true}
	}
	if err := AuthorizeCapture(context.Background(), handle, "binding", "token", "item", "", "", time.Minute, false); err != nil {
		t.Fatalf("expected allowed capture, got %v", err)
	}

	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		return store.AccessDecision{Reason: "denied"}
	}
	if err := AuthorizeCapture(context.Background(), handle, "binding", "token", "item", "", "", time.Minute, false); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("expected access denied error, got %v", err)
	}

	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		return store.AccessDecision{RequiresPrompt: true, Reason: "project_lease_required"}
	}
	if err := AuthorizeCapture(context.Background(), handle, "binding", "token", "item", "", "", time.Minute, false); err == nil || !strings.Contains(err.Error(), "project lease required for capture") {
		t.Fatalf("expected missing project grant error, got %v", err)
	}

	grantProjectLeaseFn = func(*store.Handle, string, string, store.GrantScope, time.Duration) (store.ProjectLease, error) {
		return store.ProjectLease{}, errors.New("grant project fail")
	}
	if err := AuthorizeCapture(context.Background(), handle, "binding", "token", "item", store.GrantWindow, "", time.Minute, false); err == nil || !strings.Contains(err.Error(), "grant project fail") {
		t.Fatalf("expected project grant failure, got %v", err)
	}

	grantProjectLeaseFn = func(*store.Handle, string, string, store.GrantScope, time.Duration) (store.ProjectLease, error) {
		return store.ProjectLease{}, nil
	}
	callCount := 0
	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		callCount++
		if callCount == 1 {
			return store.AccessDecision{RequiresPrompt: true, Reason: "project_lease_required"}
		}
		return store.AccessDecision{RequiresPrompt: true, Reason: "unexpected"}
	}
	if err := AuthorizeCapture(context.Background(), handle, "binding", "token", "item", store.GrantWindow, "", time.Minute, true); err == nil || !strings.Contains(err.Error(), "unsupported capture approval path") {
		t.Fatalf("expected unsupported capture path, got %v", err)
	}
}

func newBrokeropsHandle(t *testing.T) *store.Handle {
	t.Helper()
	t.Setenv(paths.EnvHome, t.TempDir())
	vaultStore, err := store.New(nil)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return handle
}

type fakeConnector struct {
	socketPath string
}

func (f fakeConnector) EnsureDaemon(context.Context) error { return nil }

func (f fakeConnector) Connect(ctx context.Context) (*runtime.Client, error) {
	return runtime.Dial(ctx, f.socketPath)
}

type fakeFailConnector struct {
	err error
}

func (f fakeFailConnector) EnsureDaemon(context.Context) error { return f.err }

func (f fakeFailConnector) Connect(context.Context) (*runtime.Client, error) { return nil, f.err }

type fakeConnectOnlyFailConnector struct {
	err error
}

func (f fakeConnectOnlyFailConnector) EnsureDaemon(context.Context) error { return nil }

func (f fakeConnectOnlyFailConnector) Connect(context.Context) (*runtime.Client, error) {
	return nil, f.err
}

type fakeBroker struct{}

func (fakeBroker) OpenSession(req runtime.OpenSessionRequest, reply *runtime.OpenSessionResponse) error {
	root := req.ProjectRoot
	*reply = runtime.OpenSessionResponse{
		SessionID:    "session-id",
		SessionToken: "auto-token",
		HostLabel:    req.HostLabel,
		ProjectRoot:  root,
		ExpiresAt:    time.Now().UTC().Add(time.Minute),
		LastSeenAt:   time.Now().UTC(),
		LocalUser:    "tester",
	}
	return nil
}

func (fakeBroker) ResolveSession(req runtime.ResolveSessionRequest, reply *runtime.ResolveSessionResponse) error {
	*reply = runtime.ResolveSessionResponse{
		Session: runtime.SessionView{
			ID:          "session-id",
			ProjectRoot: fakeSessionProjectRoot,
			HostLabel:   "tester",
			LocalUser:   "tester",
			ExpiresAt:   time.Now().UTC().Add(time.Minute),
			LastSeenAt:  time.Now().UTC(),
		},
	}
	return nil
}

type fakeErrorBroker struct {
	openErr    error
	resolveErr error
}

func (b fakeErrorBroker) OpenSession(runtime.OpenSessionRequest, *runtime.OpenSessionResponse) error {
	return b.openErr
}

func (b fakeErrorBroker) ResolveSession(runtime.ResolveSessionRequest, *runtime.ResolveSessionResponse) error {
	return b.resolveErr
}

func startBrokeropsRPCServer(t *testing.T, socketPath string) {
	startBrokeropsRPCServerWithService(t, socketPath, fakeBroker{})
}

func startBrokeropsRPCServerWithService(t *testing.T, socketPath string, service any) {
	t.Helper()
	if err := os.RemoveAll(socketPath); err != nil {
		t.Fatalf("remove stale socket: %v", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	server := rpc.NewServer()
	if err := server.RegisterName("HASP", service); err != nil {
		t.Fatalf("register fake broker: %v", err)
	}
	go func() {
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
		_ = os.Remove(socketPath)
	})
}

func TestEnsureSessionCanonicalRootAndRPCFailurePaths(t *testing.T) {
	lockBrokeropsSeams(t)
	origCanonical := canonicalProjectRootFn
	defer func() { canonicalProjectRootFn = origCanonical }()

	canonicalProjectRootFn = func(context.Context, string) (string, error) {
		return "", errors.New("canonical fail")
	}
	if _, err := EnsureSession(context.Background(), fakeConnector{}, t.TempDir(), "", "brokerops-test"); err == nil || !strings.Contains(err.Error(), "canonical fail") {
		t.Fatalf("expected canonical root failure, got %v", err)
	}

	canonicalProjectRootFn = origCanonical
	projectRoot := filepath.Join(t.TempDir(), "project")

	resolveSocket := filepath.Join("/tmp", "hasp-brokerops-resolve-error.sock")
	startBrokeropsRPCServerWithService(t, resolveSocket, fakeErrorBroker{resolveErr: errors.New("resolve fail")})
	if _, err := EnsureSession(context.Background(), fakeConnector{socketPath: resolveSocket}, projectRoot, "existing-token", "brokerops-test"); err == nil || !strings.Contains(err.Error(), "resolve fail") {
		t.Fatalf("expected resolve rpc failure, got %v", err)
	}

	openSocket := filepath.Join("/tmp", "hasp-brokerops-open-error.sock")
	startBrokeropsRPCServerWithService(t, openSocket, fakeErrorBroker{openErr: errors.New("open fail")})
	if _, err := EnsureSession(context.Background(), fakeConnector{socketPath: openSocket}, projectRoot, "", "brokerops-test"); err == nil || !strings.Contains(err.Error(), "open fail") {
		t.Fatalf("expected open rpc failure, got %v", err)
	}
}

func TestEnsureSessionWithManagerSuccessPath(t *testing.T) {
	home := t.TempDir()
	socket := filepath.Join("/tmp", "hasp-brokerops-ensure-with-manager.sock")
	t.Setenv(paths.EnvHome, home)
	t.Setenv(paths.EnvSocket, socket)
	t.Cleanup(func() { _ = os.Remove(socket) })

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
		<-errCh
	})

	projectRoot := filepath.Join(home, "project")
	session, err := EnsureSessionWithManager(context.Background(), projectRoot, "", "brokerops-test")
	if err != nil {
		t.Fatalf("ensure session with manager: %v", err)
	}
	if session.Token == "" || session.Info.ProjectRoot != projectRoot {
		t.Fatalf("unexpected session: %+v", session)
	}
}

func TestAuthorizeReferenceAndCaptureSuccessAndSecretErrors(t *testing.T) {
	handle := newBrokeropsHandle(t)
	item, err := handle.UpsertItem("db_url", store.ItemKindKV, []byte("postgres://localhost"), store.ItemMetadata{Policy: store.PolicyAccess})
	if err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	projectRoot := t.TempDir()
	binding, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": item.Name}, store.PolicyAccess, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	if _, err := AuthorizeReference(context.Background(), handle, binding.ID, projectRoot, "session-token", "secret_01", store.OperationRun, store.GrantWindow, "", "", time.Minute, ""); err == nil || !strings.Contains(err.Error(), "secret approval required") {
		t.Fatalf("expected secret approval requirement, got %v", err)
	}

	if _, err := AuthorizeReference(context.Background(), handle, binding.ID, projectRoot, "session-token", "secret_01", store.OperationWriteEnv, store.GrantWindow, store.GrantWindow, store.GrantWindow, time.Minute, filepath.Join(projectRoot, ".env.local")); err != nil {
		t.Fatalf("authorize reference write-env success: %v", err)
	}

	if err := AuthorizeCapture(context.Background(), handle, binding.ID, "session-token", "db_url", store.GrantWindow, store.GrantWindow, time.Minute, false); err != nil {
		t.Fatalf("authorize existing capture success: %v", err)
	}

	if err := AuthorizeCapture(context.Background(), handle, binding.ID, "session-token", "new_secret", store.GrantWindow, "", time.Minute, true); err != nil {
		t.Fatalf("authorize new capture success: %v", err)
	}
}

func TestAuthorizeReferenceAndItemResidualBranches(t *testing.T) {
	lockBrokeropsSeams(t)
	handle := newBrokeropsHandle(t)
	item := store.Item{Name: "api_token", Metadata: store.ItemMetadata{Policy: store.PolicySession}}
	origResolve := resolveReferenceFn
	origGet := getItemFn
	origAuthorize := authorizeFn
	origGrantSecret := grantSecretUseFn
	defer func() {
		resolveReferenceFn = origResolve
		getItemFn = origGet
		authorizeFn = origAuthorize
		grantSecretUseFn = origGrantSecret
	}()

	resolveReferenceFn = func(*store.Handle, context.Context, string, string) (store.ResolvedReference, error) {
		return store.ResolvedReference{ItemName: "api_token"}, nil
	}
	getItemFn = func(*store.Handle, string) (store.Item, error) { return item, nil }
	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		return store.AccessDecision{RequiresPrompt: true, Reason: "secret_session_grant_required"}
	}
	grantSecretUseFn = func(*store.Handle, string, string, string, store.GrantScope, time.Duration, bool) (store.SecretGrant, error) {
		return store.SecretGrant{}, errors.New("grant secret fail")
	}
	if _, err := AuthorizeReference(context.Background(), handle, "binding", t.TempDir(), "token", "secret_01", store.OperationRun, "", store.GrantSession, "", time.Minute, ""); err == nil || !strings.Contains(err.Error(), "grant secret fail") {
		t.Fatalf("expected secret grant failure, got %v", err)
	}

	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		return store.AccessDecision{RequiresPrompt: true, Reason: "write_grant_required"}
	}
	if _, err := AuthorizeReference(context.Background(), handle, "binding", t.TempDir(), "token", "secret_01", store.OperationRun, "", "", "", time.Minute, ""); err == nil || !strings.Contains(err.Error(), "capture write grant required") {
		t.Fatalf("expected write grant requirement, got %v", err)
	}

	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		return store.AccessDecision{RequiresPrompt: true, Reason: "unsupported"}
	}
	if _, err := AuthorizeReference(context.Background(), handle, "binding", t.TempDir(), "token", "secret_01", store.OperationRun, "", "", "", time.Minute, ""); err == nil || !strings.Contains(err.Error(), "unsupported approval path") {
		t.Fatalf("expected unsupported approval path, got %v", err)
	}

	authorizeFn = func(*store.Handle, store.AccessRequest) store.AccessDecision {
		return store.AccessDecision{RequiresPrompt: true, Reason: "secret_session_grant_required"}
	}
	if _, err := AuthorizeItem(handle, "binding", "token", item, store.OperationRun, "", "", time.Minute); err == nil || !strings.Contains(err.Error(), "secret approval required") {
		t.Fatalf("expected missing secret approval error, got %v", err)
	}
}

func TestEnsureClientConnectFailure(t *testing.T) {
	if _, err := ensureClient(context.Background(), fakeConnectOnlyFailConnector{err: errors.New("connect fail")}); err == nil || !strings.Contains(err.Error(), "connect fail") {
		t.Fatalf("expected connect failure, got %v", err)
	}
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
			t.Fatal("daemon exited before socket became available")
		default:
		}
		if _, err := os.Stat(socketPath); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for socket %s", socketPath)
}
