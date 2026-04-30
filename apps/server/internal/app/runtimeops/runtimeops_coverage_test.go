package runtimeops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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

type fakeKeyring struct {
	values map[string]string
	err    error
}

func (k *fakeKeyring) Set(_ context.Context, service string, account string, value string) error {
	if k.err != nil {
		return k.err
	}
	if k.values == nil {
		k.values = map[string]string{}
	}
	k.values[service+"/"+account] = value
	return nil
}

func (k *fakeKeyring) Get(service string, account string) (string, error) {
	if k.err != nil {
		return "", k.err
	}
	value, ok := k.values[service+"/"+account]
	if !ok {
		return "", store.ErrKeyringUnavailable
	}
	return value, nil
}

func (k *fakeKeyring) Delete(service string, account string) error {
	if k.err != nil {
		return k.err
	}
	delete(k.values, service+"/"+account)
	return nil
}

type fakeRuntimeStarter struct {
	socketPath string
	ensureErr  error
	connectErr error
}

func (s fakeRuntimeStarter) EnsureDaemon(context.Context) error {
	return s.ensureErr
}

func (s fakeRuntimeStarter) Connect(ctx context.Context) (*runtime.Client, error) {
	if s.connectErr != nil {
		return nil, s.connectErr
	}
	return runtime.Dial(ctx, s.socketPath)
}

type fakeRuntimeRPC struct {
	now       time.Time
	pingErr   error
	statusErr error
}

func (r *fakeRuntimeRPC) Ping(runtime.PingRequest, *runtime.PingResponse) error {
	return errors.New("use wrapper")
}

func (r *fakeRuntimeRPC) PingPtr(_ runtime.PingRequest, reply *runtime.PingResponse) error {
	if r.pingErr != nil {
		return r.pingErr
	}
	*reply = runtime.PingResponse{Name: "hasp", Version: "test", ServerTime: r.now}
	return nil
}

func (r *fakeRuntimeRPC) StatusPtr(_ runtime.StatusRequest, reply *runtime.StatusResponse) error {
	if r.statusErr != nil {
		return r.statusErr
	}
	degradedAt := r.now.Add(time.Minute)
	*reply = runtime.StatusResponse{
		SocketPath:      "/tmp/hasp.sock",
		PID:             42,
		StartedAt:       r.now,
		ActiveSessions:  1,
		AuditDegraded:   true,
		AuditDegradedAt: &degradedAt,
	}
	return nil
}

type haspRuntimeRPC struct {
	inner *fakeRuntimeRPC
}

func (h haspRuntimeRPC) Ping(req runtime.PingRequest, reply *runtime.PingResponse) error {
	return h.inner.PingPtr(req, reply)
}

func (h haspRuntimeRPC) Status(req runtime.StatusRequest, reply *runtime.StatusResponse) error {
	return h.inner.StatusPtr(req, reply)
}

func startRuntimeRPC(t *testing.T, fake *fakeRuntimeRPC) string {
	t.Helper()
	if fake.now.IsZero() {
		fake.now = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	}
	socket := filepath.Join(os.TempDir(), fmt.Sprintf("hasp-runtimeops-%d-%d.sock", os.Getpid(), time.Now().UnixNano()))
	_ = os.Remove(socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := rpc.NewServer()
	if err := server.RegisterName("HASP", haspRuntimeRPC{inner: fake}); err != nil {
		t.Fatalf("register: %v", err)
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
		_ = os.Remove(socket)
		<-done
	})
	return socket
}

func newRuntimeStoreHandle(t *testing.T, home string) (*store.Store, *store.Handle) {
	t.Helper()
	t.Setenv(paths.EnvHome, home)
	vaultStore, err := store.New(&fakeKeyring{})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "master-password"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "master-password")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.UpsertItem("ALPHA", store.ItemKindKV, []byte("secret-value"), store.ItemMetadata{}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	return vaultStore, handle
}

func fullRuntimeDeps(t *testing.T, fake *fakeRuntimeRPC) Deps {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	vaultStore, handle := newRuntimeStoreHandle(t, home)
	socket := startRuntimeRPC(t, fake)
	return Deps{
		OpenVault:     func(context.Context) (*store.Handle, error) { return handle, nil },
		NewVaultStore: func() (*store.Store, error) { return vaultStore, nil },
		NewStarter:    func() (Starter, error) { return fakeRuntimeStarter{socketPath: socket}, nil },
		TerminalColumns: func() int {
			return 20
		},
		RenderJSONOrHuman: func(_ context.Context, stdout io.Writer, _ bool, _ any, human func(io.Writer) error) error {
			return human(stdout)
		},
		WriteJSONResponse: func(w io.Writer, payload any) error {
			_, err := fmt.Fprint(w, "json")
			return err
		},
		RenderBackupResult: func(out io.Writer, title string, lead string, path string, checkpoint store.AuditCheckpoint) error {
			_, err := fmt.Fprintf(out, "%s:%s:%d", title, path, checkpoint.Sequence)
			return err
		},
		RenderStatusHuman: renderStatusHumanFallback,
		RenderPingJSONOrHuman: func(_ context.Context, stdout io.Writer, _ bool, reply runtime.PingResponse) error {
			_, err := stdout.Write([]byte(reply.Name))
			return err
		},
		RenderNotRunning: func(stdout io.Writer, jsonOutput bool) error {
			_, err := fmt.Fprintf(stdout, "not-running:%v", jsonOutput)
			return err
		},
		ReadPassphrase: func(bool, int, string, string) (string, error) { return "backup-passphrase", nil },
		ExpandUserPath: func(path string) (string, error) {
			return strings.Replace(path, "~", home, 1), nil
		},
		EnsureProjectBinding: func(context.Context, *store.Handle, string) (store.Binding, []store.VisibleReference, bool, error) {
			return store.Binding{ID: "binding", CanonicalRoot: "/repo"}, []store.VisibleReference{{Alias: "ALPHA", Kind: store.ItemKindKV, PolicyLevel: store.PolicySession}}, true, nil
		},
		LoadMasterPassword:    func() (string, error) { return "restored-password", nil },
		IsHelpArg:             nil,
		PrintHelpTopic:        nil,
		GlobalJSON:            func(context.Context) bool { return false },
		ErrArgvPassphrase:     errors.New("argv passphrase"),
		ErrArgvMasterPassword: errors.New("argv master"),
		NewRuntimeManager: func() (*runtime.Manager, error) {
			t.Setenv(paths.EnvHome, home)
			return runtime.NewManager()
		},
		NewInternalError: func(msg string) error { return errors.New("internal:" + msg) },
	}
}

func TestRuntimeCommandSuccessPaths(t *testing.T) {
	ctx := context.Background()
	deps := fullRuntimeDeps(t, &fakeRuntimeRPC{})
	backupPath := filepath.Join(t.TempDir(), "hasp.backup.json")
	var out bytes.Buffer

	if err := RuntimeCommand(ctx, deps, []string{"export-backup", "--output", backupPath}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("export: %v", err)
	}
	if err := RuntimeCommand(ctx, deps, []string{"restore-backup", "--input", backupPath}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("restore: %v", err)
	}

	successes := [][]string{
		{"ping"},
		{"status"},
		{"tui", "--project-root", "~/repo"},
		{"daemon"},
	}
	for _, args := range successes {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			out.Reset()
			if err := RuntimeCommand(ctx, deps, args, strings.NewReader(""), &out, io.Discard); err != nil {
				t.Fatalf("RuntimeCommand(%v): %v", args, err)
			}
		})
	}

	origRun := managerRunDaemon
	origStart := managerStartDaemon
	origStop := managerStopDaemon
	t.Cleanup(func() {
		managerRunDaemon = origRun
		managerStartDaemon = origStart
		managerStopDaemon = origStop
	})
	managerRunDaemon = func(*runtime.Manager, context.Context) error { return nil }
	managerStartDaemon = func(*runtime.Manager, context.Context) error { return nil }
	managerStopDaemon = func(*runtime.Manager) error { return nil }
	for _, args := range [][]string{{"daemon", "serve"}, {"daemon", "start"}, {"daemon", "stop"}, {"daemon", "status"}} {
		if err := RuntimeCommand(ctx, deps, args, strings.NewReader(""), &out, io.Discard); err != nil {
			t.Fatalf("daemon %v: %v", args, err)
		}
	}
}

func TestRuntimeCommandFallbacks(t *testing.T) {
	ctx := context.Background()
	deps := fullRuntimeDeps(t, &fakeRuntimeRPC{})
	var out bytes.Buffer

	if !globalJSON(ctx, deps) {
		deps.GlobalJSON = func(context.Context) bool { return true }
	}
	if !globalJSON(ctx, deps) {
		t.Fatal("expected global json")
	}
	deps.GlobalJSON = nil
	if globalJSON(ctx, deps) {
		t.Fatal("unexpected global json fallback")
	}

	if err := renderBackupResultFn(Deps{}, &out, "Title", "Lead", "/tmp/x", store.AuditCheckpoint{Sequence: 3, Hash: "abc"}); err != nil {
		t.Fatalf("backup fallback: %v", err)
	}
	if got := clipForTerminal("/long/path/value", 4, 10); !strings.HasPrefix(got, "…") {
		t.Fatalf("clipped path %q", got)
	}
	if got := clipForTerminal("short", 4, 20); got != "short" {
		t.Fatalf("unclipped path %q", got)
	}
	if got := clipForTerminal("short", 4, 0); got != "short" {
		t.Fatalf("unknown cols path %q", got)
	}
	if got := clipForTerminal("short", 100, 10); got != "short" {
		t.Fatalf("negative budget path %q", got)
	}

	deps.RenderBackupResult = nil
	if err := RuntimeCommand(ctx, deps, []string{"export-backup", "--output", filepath.Join(t.TempDir(), "backup.json")}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("export fallback render: %v", err)
	}
	deps.RenderJSONOrHuman = nil
	deps.GlobalJSON = func(context.Context) bool { return true }
	if err := RuntimeCommand(ctx, deps, []string{"export-backup", "--output", filepath.Join(t.TempDir(), "backup.json")}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("export json fallback: %v", err)
	}
	deps.WriteJSONResponse = nil
	if err := renderNotRunningFn(deps, &out, true); err != nil {
		t.Fatalf("not running json fallback: %v", err)
	}
	if err := renderNotRunningFn(deps, &out, false); err != nil {
		t.Fatalf("not running text fallback: %v", err)
	}
	if client := connectIfRunningFn(ctx, Deps{}, nil); client != nil {
		t.Fatal("unexpected client")
	}
	if client := connectIfRunningFn(ctx, Deps{}, fakeRuntimeStarter{connectErr: errors.New("connect")}); client != nil {
		t.Fatal("unexpected failed-connect client")
	}
}

func TestRuntimeCommandErrorBranches(t *testing.T) {
	ctx := context.Background()
	base := fullRuntimeDeps(t, &fakeRuntimeRPC{})
	cases := []struct {
		name string
		args []string
		mut  func(*Deps)
	}{
		{"unknown empty", nil, nil},
		{"unknown", []string{"wat"}, nil},
		{"export parse", []string{"export-backup", "--bad"}, nil},
		{"export argv", []string{"export-backup", "--output", "x", "--recovery-passphrase", "secret"}, nil},
		{"export usage", []string{"export-backup"}, nil},
		{"export read pass", []string{"export-backup", "--output", "x"}, func(d *Deps) {
			d.ReadPassphrase = func(bool, int, string, string) (string, error) { return "", errors.New("pass") }
		}},
		{"export expand", []string{"export-backup", "--output", "~bad"}, func(d *Deps) {
			d.ExpandUserPath = func(string) (string, error) { return "", errors.New("expand") }
		}},
		{"export open nil", []string{"export-backup", "--output", "x"}, func(d *Deps) { d.OpenVault = nil }},
		{"export open", []string{"export-backup", "--output", "x"}, func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"export backup", []string{"export-backup", "--output", t.TempDir()}, nil},
		{"restore parse", []string{"restore-backup", "--bad"}, nil},
		{"restore argv pass", []string{"restore-backup", "--input", "x", "--recovery-passphrase", "secret"}, nil},
		{"restore argv master", []string{"restore-backup", "--input", "x", "--master-password", "secret"}, nil},
		{"restore usage", []string{"restore-backup"}, nil},
		{"restore read pass", []string{"restore-backup", "--input", "x"}, func(d *Deps) {
			d.ReadPassphrase = func(bool, int, string, string) (string, error) { return "", errors.New("pass") }
		}},
		{"restore load master", []string{"restore-backup", "--input", "x"}, func(d *Deps) {
			d.LoadMasterPassword = func() (string, error) { return "", errors.New("master") }
		}},
		{"restore expand", []string{"restore-backup", "--input", "~bad"}, func(d *Deps) {
			d.ExpandUserPath = func(string) (string, error) { return "", errors.New("expand") }
		}},
		{"restore store nil", []string{"restore-backup", "--input", "x"}, func(d *Deps) { d.NewVaultStore = nil }},
		{"restore store", []string{"restore-backup", "--input", "x"}, func(d *Deps) {
			d.NewVaultStore = func() (*store.Store, error) { return nil, errors.New("store") }
		}},
		{"restore backup", []string{"restore-backup", "--input", "missing"}, nil},
		{"ping parse", []string{"ping", "--bad"}, nil},
		{"ping starter", []string{"ping"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return nil, errors.New("starter") }
		}},
		{"status parse", []string{"status", "--bad"}, nil},
		{"status starter", []string{"status"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return nil, errors.New("starter") }
		}},
		{"tui parse", []string{"tui", "--bad"}, nil},
		{"tui expand", []string{"tui", "--project-root", "~"}, func(d *Deps) {
			d.ExpandUserPath = func(string) (string, error) { return "", errors.New("expand") }
		}},
		{"tui open nil", []string{"tui"}, func(d *Deps) { d.OpenVault = nil }},
		{"tui open", []string{"tui"}, func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"tui binding nil", []string{"tui"}, func(d *Deps) { d.EnsureProjectBinding = nil }},
		{"tui binding", []string{"tui"}, func(d *Deps) {
			d.EnsureProjectBinding = func(context.Context, *store.Handle, string) (store.Binding, []store.VisibleReference, bool, error) {
				return store.Binding{}, nil, false, errors.New("bind")
			}
		}},
		{"daemon manager", []string{"daemon", "start"}, func(d *Deps) {
			d.NewRuntimeManager = func() (*runtime.Manager, error) { return nil, errors.New("manager") }
		}},
		{"daemon unknown", []string{"daemon", "wat"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := base
			if tc.mut != nil {
				tc.mut(&deps)
			}
			if err := RuntimeCommand(ctx, deps, tc.args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
				t.Fatalf("expected error for %v", tc.args)
			}
		})
	}
}

func TestRuntimeRPCBranches(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		args []string
		fake fakeRuntimeRPC
	}{
		{"ping rpc", []string{"ping"}, fakeRuntimeRPC{pingErr: errors.New("ping")}},
		{"status rpc", []string{"status"}, fakeRuntimeRPC{statusErr: errors.New("status")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := tc.fake
			deps := fullRuntimeDeps(t, &fake)
			if err := RuntimeCommand(ctx, deps, tc.args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRuntimeOptionalRenderingBranches(t *testing.T) {
	ctx := context.Background()
	deps := fullRuntimeDeps(t, &fakeRuntimeRPC{})
	var out bytes.Buffer
	deps.ConnectIfRunning = func(context.Context, Starter) *runtime.Client { return nil }
	if err := RuntimeCommand(ctx, deps, []string{"ping", "--json"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("ping not running: %v", err)
	}
	if err := RuntimeCommand(ctx, deps, []string{"status", "--json"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("status not running: %v", err)
	}

	deps = fullRuntimeDeps(t, &fakeRuntimeRPC{})
	deps.RenderPingJSONOrHuman = nil
	deps.WriteJSONResponse = nil
	deps.RenderJSONOrHuman = nil
	if err := RuntimeCommand(ctx, deps, []string{"ping"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("ping minimal: %v", err)
	}
	deps = fullRuntimeDeps(t, &fakeRuntimeRPC{})
	deps.RenderPingJSONOrHuman = nil
	deps.WriteJSONResponse = nil
	if err := RuntimeCommand(ctx, deps, []string{"ping", "--json"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("ping render json fallback: %v", err)
	}

	deps = fullRuntimeDeps(t, &fakeRuntimeRPC{})
	deps.RenderStatusHuman = nil
	if err := RuntimeCommand(ctx, deps, []string{"status"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("status fallback: %v", err)
	}
	deps = fullRuntimeDeps(t, &fakeRuntimeRPC{})
	deps.RenderStatusHuman = nil
	deps.WriteJSONResponse = nil
	if err := RuntimeCommand(ctx, deps, []string{"status", "--json"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("status json render fallback: %v", err)
	}
}

func TestRuntimeRemainingFallbackBranches(t *testing.T) {
	ctx := context.Background()
	deps := fullRuntimeDeps(t, &fakeRuntimeRPC{})
	var out bytes.Buffer
	if err := RuntimeCommand(ctx, func() Deps {
		d := deps
		d.ErrArgvPassphrase = nil
		return d
	}(), []string{"export-backup", "--output", "x", "--recovery-passphrase", "secret"}, strings.NewReader(""), &out, io.Discard); err == nil {
		t.Fatal("expected default argv passphrase export error")
	}
	if err := RuntimeCommand(ctx, func() Deps {
		d := deps
		d.ErrArgvPassphrase = nil
		return d
	}(), []string{"restore-backup", "--input", "x", "--recovery-passphrase", "secret"}, strings.NewReader(""), &out, io.Discard); err == nil {
		t.Fatal("expected default argv passphrase restore error")
	}
	if err := RuntimeCommand(ctx, func() Deps {
		d := deps
		d.ErrArgvMasterPassword = nil
		return d
	}(), []string{"restore-backup", "--input", "x", "--master-password", "secret"}, strings.NewReader(""), &out, io.Discard); err == nil {
		t.Fatal("expected default argv master restore error")
	}

	t.Setenv("HASP_BACKUP_PASSPHRASE", "backup-passphrase")
	t.Setenv("HASP_MASTER_PASSWORD", "restored-password")
	backupPath := filepath.Join(t.TempDir(), "backup.json")
	d := deps
	d.ReadPassphrase = nil
	d.RenderJSONOrHuman = nil
	d.RenderBackupResult = nil
	if err := RuntimeCommand(ctx, d, []string{"export-backup", "--output", backupPath}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("export env/final fallback: %v", err)
	}
	d = deps
	d.ReadPassphrase = nil
	d.LoadMasterPassword = nil
	d.RenderJSONOrHuman = nil
	d.RenderBackupResult = nil
	if err := RuntimeCommand(ctx, d, []string{"restore-backup", "--input", backupPath}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("restore env/final fallback: %v", err)
	}
	d = deps
	d.LoadMasterPassword = nil
	t.Setenv("HASP_MASTER_PASSWORD", "")
	if err := RuntimeCommand(ctx, d, []string{"restore-backup", "--input", backupPath}, strings.NewReader(""), &out, io.Discard); err == nil {
		t.Fatal("expected missing env master password")
	}
	t.Setenv("HASP_MASTER_PASSWORD", "restored-password")
	d = deps
	d.RenderJSONOrHuman = nil
	d.GlobalJSON = func(context.Context) bool { return true }
	if err := RuntimeCommand(ctx, d, []string{"restore-backup", "--input", backupPath}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("restore write-json fallback: %v", err)
	}
	d.WriteJSONResponse = nil
	d.RenderBackupResult = nil
	if err := RuntimeCommand(ctx, d, []string{"restore-backup", "--input", backupPath}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("restore json final fallback: %v", err)
	}

	if err := renderNotRunningFn(Deps{WriteJSONResponse: func(w io.Writer, payload any) error {
		_, err := w.Write([]byte("json"))
		return err
	}}, &out, true); err != nil {
		t.Fatalf("not running write-json: %v", err)
	}
	if err := renderNotRunningFn(Deps{}, &out, true); err != nil {
		t.Fatalf("not running minimal json: %v", err)
	}
	if err := renderNotRunningFn(Deps{}, &out, false); err != nil {
		t.Fatalf("not running minimal text: %v", err)
	}

	d = deps
	d.RenderPingJSONOrHuman = nil
	if err := RuntimeCommand(ctx, d, []string{"ping", "--json"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("ping write-json fallback: %v", err)
	}
	if err := RuntimeCommand(ctx, deps, []string{"status", "--json"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("status write-json: %v", err)
	}
	if err := RuntimeCommand(ctx, deps, []string{"tui", "--json"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("tui write-json: %v", err)
	}
	d = deps
	d.WriteJSONResponse = nil
	if err := RuntimeCommand(ctx, d, []string{"tui", "--json"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("tui minimal json: %v", err)
	}

	origStart := managerStartDaemon
	t.Cleanup(func() { managerStartDaemon = origStart })
	managerStartDaemon = func(*runtime.Manager, context.Context) error { return nil }
	d = deps
	d.NewRuntimeManager = nil
	t.Setenv(paths.EnvHome, filepath.Join(t.TempDir(), "manager-home"))
	if err := RuntimeCommand(ctx, d, []string{"daemon", "start"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("daemon default manager: %v", err)
	}
}

func TestDaemonStopErrorBranches(t *testing.T) {
	ctx := context.Background()
	deps := fullRuntimeDeps(t, &fakeRuntimeRPC{})
	origStop := managerStopDaemon
	t.Cleanup(func() { managerStopDaemon = origStop })
	managerStopDaemon = func(*runtime.Manager) error { return errors.New("process already finished") }
	if err := RuntimeCommand(ctx, deps, []string{"daemon", "stop"}, strings.NewReader(""), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "internal") {
		t.Fatalf("expected internal not-running error, got %v", err)
	}
	deps.NewInternalError = nil
	if err := RuntimeCommand(ctx, deps, []string{"daemon", "stop"}, strings.NewReader(""), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("expected not-running error, got %v", err)
	}
	managerStopDaemon = func(*runtime.Manager) error { return errors.New("stop") }
	if err := RuntimeCommand(ctx, deps, []string{"daemon", "stop"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected stop error")
	}
}
