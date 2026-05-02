package sessionops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/app/vaultops"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type fakeSessionStarter struct {
	socketPath string
	ensureErr  error
	connectErr error
}

func (s fakeSessionStarter) EnsureDaemon(context.Context) error {
	return s.ensureErr
}

func (s fakeSessionStarter) Connect(ctx context.Context) (*runtime.Client, error) {
	if s.connectErr != nil {
		return nil, s.connectErr
	}
	return runtime.Dial(ctx, s.socketPath)
}

type fakeSessionRPC struct {
	now              time.Time
	openErr          error
	resolveErr       error
	statusErr        error
	revokeErr        error
	revokeAllErr     error
	revokeSessionOK  bool
	agentSafe        bool
	revokedAll       int
	resolveProject   string
	resolveLocalUser string
}

func (s *fakeSessionRPC) OpenSession(req runtime.OpenSessionRequest, reply *runtime.OpenSessionResponse) error {
	if s.openErr != nil {
		return s.openErr
	}
	*reply = runtime.OpenSessionResponse{
		SessionID:   "sid",
		HostLabel:   req.HostLabel,
		ProjectRoot: req.ProjectRoot,
		LastSeenAt:  s.now,
		ExpiresAt:   s.now.Add(time.Minute),
	}
	return nil
}

func (s *fakeSessionRPC) ResolveSession(req runtime.ResolveSessionRequest, reply *runtime.ResolveSessionResponse) error {
	if s.resolveErr != nil {
		return s.resolveErr
	}
	localUser := s.resolveLocalUser
	if localUser == "" {
		localUser = "me"
	}
	project := s.resolveProject
	if project == "" {
		project = "/repo"
	}
	*reply = runtime.ResolveSessionResponse{Session: runtime.SessionView{
		ID:          req.SessionToken,
		LocalUser:   localUser,
		HostLabel:   "agent",
		ProjectRoot: project,
		AgentSafe:   s.agentSafe,
		LastSeenAt:  s.now,
		ExpiresAt:   s.now.Add(time.Minute),
	}}
	return nil
}

func (s *fakeSessionRPC) Status(runtime.StatusRequest, *runtime.StatusResponse) error {
	return errors.New("use pointer form")
}

func (s *fakeSessionRPC) StatusPtr(_ runtime.StatusRequest, reply *runtime.StatusResponse) error {
	if s.statusErr != nil {
		return s.statusErr
	}
	*reply = runtime.StatusResponse{Sessions: []runtime.SessionView{
		{ID: "mine", LocalUser: "me", HostLabel: "host", ProjectRoot: "/repo", AgentSafe: true, ConsumerName: "codex", LastSeenAt: s.now, ExpiresAt: s.now.Add(time.Minute)},
		{ID: "other", LocalUser: "you", HostLabel: "other", ProjectRoot: "/repo", LastSeenAt: s.now, ExpiresAt: s.now.Add(-time.Minute)},
	}}
	return nil
}

func (s *fakeSessionRPC) RevokeSession(_ runtime.RevokeSessionRequest, reply *runtime.RevokeSessionResponse) error {
	if s.revokeErr != nil {
		return s.revokeErr
	}
	*reply = runtime.RevokeSessionResponse{Revoked: s.revokeSessionOK, RevokedCount: 1}
	return nil
}

func (s *fakeSessionRPC) RevokeAllSessions(_ runtime.RevokeAllSessionsRequest, reply *runtime.RevokeAllSessionsResponse) error {
	if s.revokeAllErr != nil {
		return s.revokeAllErr
	}
	*reply = runtime.RevokeAllSessionsResponse{RevokedCount: s.revokedAll}
	return nil
}

type haspSessionRPC struct {
	inner *fakeSessionRPC
}

func (h haspSessionRPC) OpenSession(req runtime.OpenSessionRequest, reply *runtime.OpenSessionResponse) error {
	return h.inner.OpenSession(req, reply)
}
func (h haspSessionRPC) ResolveSession(req runtime.ResolveSessionRequest, reply *runtime.ResolveSessionResponse) error {
	return h.inner.ResolveSession(req, reply)
}
func (h haspSessionRPC) Status(req runtime.StatusRequest, reply *runtime.StatusResponse) error {
	return h.inner.StatusPtr(req, reply)
}
func (h haspSessionRPC) RevokeSession(req runtime.RevokeSessionRequest, reply *runtime.RevokeSessionResponse) error {
	return h.inner.RevokeSession(req, reply)
}
func (h haspSessionRPC) RevokeAllSessions(req runtime.RevokeAllSessionsRequest, reply *runtime.RevokeAllSessionsResponse) error {
	return h.inner.RevokeAllSessions(req, reply)
}

func startSessionRPC(t *testing.T, fake *fakeSessionRPC) string {
	t.Helper()
	socket := filepath.Join(os.TempDir(), fmt.Sprintf("hasp-sessionops-%d-%d.sock", os.Getpid(), time.Now().UnixNano()))
	_ = os.Remove(socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := rpc.NewServer()
	if err := server.RegisterName("HASP", haspSessionRPC{inner: fake}); err != nil {
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

func fullSessionDeps(t *testing.T, fake *fakeSessionRPC) Deps {
	t.Helper()
	if fake.now.IsZero() {
		fake.now = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	}
	fake.agentSafe = true
	fake.revokeSessionOK = true
	fake.revokedAll = 2
	socket := startSessionRPC(t, fake)
	return Deps{
		OpenVault: func(context.Context) (*store.Handle, error) { return &store.Handle{}, nil },
		CanonicalProjectRoot: func(_ context.Context, root string) (string, error) {
			if strings.TrimSpace(root) == "" {
				return "/repo", nil
			}
			return root, nil
		},
		EnsureProjectBinding: func(context.Context, *store.Handle, string) error { return nil },
		GetItem: func(_ *store.Handle, name string) (store.Item, error) {
			return store.Item{Name: name, Kind: store.ItemKindKV}, nil
		},
		ResolveBindingView: func(context.Context, *store.Handle, string) (store.Binding, []store.VisibleReference, error) {
			return store.Binding{ID: "binding"}, nil, nil
		},
		NewStarter: func() (Starter, error) { return fakeSessionStarter{socketPath: socket}, nil },
		RenderJSONOrHuman: func(_ context.Context, stdout io.Writer, _ bool, _ any, human func(io.Writer) error) error {
			return human(stdout)
		},
		RenderSimpleAction: func(_ context.Context, out io.Writer, title string, lead string, pairs ...[2]string) error {
			_, err := fmt.Fprintf(out, "%s:%s", title, pairs[0][1])
			return err
		},
		GlobalJSON: func(context.Context) bool { return false },
		ParsePlaintextAction: func(value string) (store.PlaintextAction, error) {
			switch value {
			case string(store.PlaintextReveal):
				return store.PlaintextReveal, nil
			case string(store.PlaintextCopy):
				return store.PlaintextCopy, nil
			default:
				return "", errors.New("action")
			}
		},
		ParseMutationAction: func(value string) (store.SecretMutationAction, error) {
			switch value {
			case string(store.SecretMutationDelete):
				return store.SecretMutationDelete, nil
			case string(store.SecretMutationExpose):
				return store.SecretMutationExpose, nil
			case string(store.SecretMutationHide):
				return store.SecretMutationHide, nil
			default:
				return "", errors.New("mutation")
			}
		},
		ParseGrantScope: func(value string) store.GrantScope { return store.GrantScope(value) },
		RenderSessionOpenResult: func(out io.Writer, sessionID string, hostLabel string, projectRoot string, expiresAt string) error {
			_, err := fmt.Fprintf(out, "%s:%s:%s:%s", sessionID, hostLabel, projectRoot, expiresAt)
			return err
		},
		RenderSessionResolveResult: func(out io.Writer, reply runtime.ResolveSessionResponse) error {
			_, err := fmt.Fprintf(out, "%s:%s", reply.Session.ID, reply.Session.HostLabel)
			return err
		},
		GrantOps: func() vaultops.GrantOpsDeps {
			return vaultops.GrantOpsDeps{
				RevokeAllGrants: func(*store.Handle) (int, error) { return 3, nil },
				DisableConvenienceUnlock: func(*store.Handle, context.Context) (bool, error) {
					return true, nil
				},
			}
		},
		ExpandUserPath: func(path string) (string, error) {
			return strings.Replace(path, "~", "/home/test", 1), nil
		},
		DefaultLocalDeps: func() LocalDeps {
			return LocalDeps{
				Approve: func(runtime.SessionView, string, store.PlaintextAction) error { return nil },
				UseGrant: func(*store.Handle, string, string, store.PlaintextAction, time.Duration) (store.PlaintextGrant, error) {
					expiresAt := fake.now.Add(time.Minute)
					return store.PlaintextGrant{Scope: store.GrantOnce, ExpiresAt: &expiresAt}, nil
				},
				ApproveMutation: func(runtime.SessionView, string, store.SecretMutationAction) error { return nil },
				UseMutationGrant: func(*store.Handle, string, string, string, store.SecretMutationAction, time.Duration) (store.MutationGrant, error) {
					expiresAt := fake.now.Add(time.Minute)
					return store.MutationGrant{Scope: store.GrantOnce, ExpiresAt: &expiresAt}, nil
				},
				LocalUser: func() (string, error) { return "me", nil },
			}
		},
		DefaultConfirmPlaintextGrantDeps: func() ConfirmPlaintextGrantDeps {
			return ConfirmPlaintextGrantDeps{UnderTest: func() bool { return true }}
		},
		GlobalColorOptions: func(context.Context, io.Writer) ColorOptions {
			return ColorOptions{Verbose: true}
		},
	}
}

func TestSessionCommandSuccessPaths(t *testing.T) {
	ctx := context.Background()
	deps := fullSessionDeps(t, &fakeSessionRPC{})
	var out bytes.Buffer
	successes := [][]string{
		{"open", "--host-label", "agent", "--project-root", "~/repo"},
		{"grant-plaintext", "--token", "tok", "--item", "ALPHA", "--action", "reveal"},
		{"grant-mutation", "--token", "tok", "--item", "ALPHA", "--action", "expose"},
		{"resolve", "--token", "tok"},
		{"revoke", "--token", "tok"},
		{"revoke", "--all"},
		{"list"},
		{"list", "--mine"},
		{"help"},
	}
	for _, args := range successes {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			out.Reset()
			if err := SessionCommand(ctx, deps, args, strings.NewReader(""), &out, io.Discard); err != nil {
				t.Fatalf("SessionCommand(%v): %v", args, err)
			}
		})
	}
	if err := SessionCommand(ctx, deps, nil, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("empty help: %v", err)
	}
	if err := sessionGrantPlaintext(ctx, deps, []string{"--token", "tok", "--item", "ALPHA", "--action", "copy"}, &out, &LocalDeps{
		Approve: func(runtime.SessionView, string, store.PlaintextAction) error { return nil },
		UseGrant: func(*store.Handle, string, string, store.PlaintextAction, time.Duration) (store.PlaintextGrant, error) {
			expiresAt := time.Now()
			return store.PlaintextGrant{Scope: store.GrantOnce, ExpiresAt: &expiresAt}, nil
		},
	}); err != nil {
		t.Fatalf("grant with local deps: %v", err)
	}
	if err := sessionGrantMutation(ctx, deps, []string{"--token", "tok", "--item", "ALPHA", "--action", "hide"}, &out, &LocalDeps{
		ApproveMutation: func(runtime.SessionView, string, store.SecretMutationAction) error { return nil },
		UseMutationGrant: func(*store.Handle, string, string, string, store.SecretMutationAction, time.Duration) (store.MutationGrant, error) {
			expiresAt := time.Now()
			return store.MutationGrant{Scope: store.GrantOnce, ExpiresAt: &expiresAt}, nil
		},
	}); err != nil {
		t.Fatalf("mutation grant with local deps: %v", err)
	}
}

func TestSessionCommandErrorBranches(t *testing.T) {
	ctx := context.Background()
	base := fullSessionDeps(t, &fakeSessionRPC{})
	cases := []struct {
		name string
		args []string
		mut  func(*Deps)
	}{
		{"unknown", []string{"wat"}, nil},
		{"open parse", []string{"open", "--bad"}, nil},
		{"open expand", []string{"open", "--project-root", "~"}, func(d *Deps) {
			d.ExpandUserPath = func(string) (string, error) { return "", errors.New("expand") }
		}},
		{"open canonical", []string{"open"}, func(d *Deps) {
			d.CanonicalProjectRoot = func(context.Context, string) (string, error) { return "", errors.New("root") }
		}},
		{"open vault", []string{"open"}, func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"open binding", []string{"open"}, func(d *Deps) {
			d.EnsureProjectBinding = func(context.Context, *store.Handle, string) error { return errors.New("bind") }
		}},
		{"open starter missing", []string{"open"}, func(d *Deps) { d.NewStarter = nil }},
		{"open starter", []string{"open"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return nil, errors.New("starter") }
		}},
		{"open ensure", []string{"open"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return fakeSessionStarter{ensureErr: errors.New("ensure")}, nil }
		}},
		{"open connect", []string{"open"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return fakeSessionStarter{connectErr: errors.New("connect")}, nil }
		}},
		{"open renderer", []string{"open"}, func(d *Deps) { d.RenderJSONOrHuman = nil }},
		{"open open renderer", []string{"open"}, func(d *Deps) { d.RenderSessionOpenResult = nil }},
		{"grant parse", []string{"grant-plaintext", "--bad"}, nil},
		{"grant usage", []string{"grant-plaintext"}, nil},
		{"grant parse action missing", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal"}, func(d *Deps) {
			d.ParsePlaintextAction = nil
		}},
		{"grant parse scope missing", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal"}, func(d *Deps) {
			d.ParseGrantScope = nil
		}},
		{"grant bad action", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "bad"}, nil},
		{"grant bad scope", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal", "--scope", "session"}, nil},
		{"grant starter missing", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal"}, func(d *Deps) { d.NewStarter = nil }},
		{"grant starter", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return nil, errors.New("starter") }
		}},
		{"grant ensure", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return fakeSessionStarter{ensureErr: errors.New("ensure")}, nil }
		}},
		{"grant vault missing", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal"}, func(d *Deps) { d.OpenVault = nil }},
		{"grant vault", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal"}, func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"grant get missing", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal"}, func(d *Deps) { d.GetItem = nil }},
		{"grant get", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal"}, func(d *Deps) {
			d.GetItem = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("get") }
		}},
		{"grant approve", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal"}, func(d *Deps) {
			d.DefaultLocalDeps = func() LocalDeps {
				return LocalDeps{
					Approve: func(runtime.SessionView, string, store.PlaintextAction) error { return errors.New("approve") },
					UseGrant: func(*store.Handle, string, string, store.PlaintextAction, time.Duration) (store.PlaintextGrant, error) {
						return store.PlaintextGrant{}, nil
					},
				}
			}
		}},
		{"grant use", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal"}, func(d *Deps) {
			d.DefaultLocalDeps = func() LocalDeps {
				return LocalDeps{
					Approve: func(runtime.SessionView, string, store.PlaintextAction) error { return nil },
					UseGrant: func(*store.Handle, string, string, store.PlaintextAction, time.Duration) (store.PlaintextGrant, error) {
						return store.PlaintextGrant{}, errors.New("grant")
					},
				}
			}
		}},
		{"grant renderer missing", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal"}, func(d *Deps) { d.RenderJSONOrHuman = nil }},
		{"grant action renderer missing", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal"}, func(d *Deps) { d.RenderSimpleAction = nil }},
		{"mutation parse", []string{"grant-mutation", "--bad"}, nil},
		{"mutation usage", []string{"grant-mutation"}, nil},
		{"mutation parse action missing", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) {
			d.ParseMutationAction = nil
		}},
		{"mutation parse scope missing", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) {
			d.ParseGrantScope = nil
		}},
		{"mutation bad action", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "bad"}, nil},
		{"mutation bad scope", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose", "--scope", "session"}, nil},
		{"mutation starter missing", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) { d.NewStarter = nil }},
		{"mutation starter", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return nil, errors.New("starter") }
		}},
		{"mutation ensure", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return fakeSessionStarter{ensureErr: errors.New("ensure")}, nil }
		}},
		{"mutation vault missing", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) { d.OpenVault = nil }},
		{"mutation vault", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"mutation get missing", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) { d.GetItem = nil }},
		{"mutation get", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) {
			d.GetItem = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("get") }
		}},
		{"mutation binding missing", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) { d.ResolveBindingView = nil }},
		{"mutation binding", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) {
			d.ResolveBindingView = func(context.Context, *store.Handle, string) (store.Binding, []store.VisibleReference, error) {
				return store.Binding{}, nil, errors.New("binding")
			}
		}},
		{"mutation approve local missing", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) {
			d.DefaultLocalDeps = func() LocalDeps {
				return LocalDeps{
					UseMutationGrant: func(*store.Handle, string, string, string, store.SecretMutationAction, time.Duration) (store.MutationGrant, error) {
						return store.MutationGrant{}, nil
					},
				}
			}
		}},
		{"mutation use local missing", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) {
			d.DefaultLocalDeps = func() LocalDeps {
				return LocalDeps{
					ApproveMutation: func(runtime.SessionView, string, store.SecretMutationAction) error { return nil },
				}
			}
		}},
		{"mutation approve", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) {
			d.DefaultLocalDeps = func() LocalDeps {
				return LocalDeps{
					ApproveMutation: func(runtime.SessionView, string, store.SecretMutationAction) error { return errors.New("approve") },
					UseMutationGrant: func(*store.Handle, string, string, string, store.SecretMutationAction, time.Duration) (store.MutationGrant, error) {
						return store.MutationGrant{}, nil
					},
				}
			}
		}},
		{"mutation use", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) {
			d.DefaultLocalDeps = func() LocalDeps {
				return LocalDeps{
					ApproveMutation: func(runtime.SessionView, string, store.SecretMutationAction) error { return nil },
					UseMutationGrant: func(*store.Handle, string, string, string, store.SecretMutationAction, time.Duration) (store.MutationGrant, error) {
						return store.MutationGrant{}, errors.New("grant")
					},
				}
			}
		}},
		{"mutation renderer missing", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) { d.RenderJSONOrHuman = nil }},
		{"mutation action renderer missing", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, func(d *Deps) { d.RenderSimpleAction = nil }},
		{"resolve parse", []string{"resolve", "--bad"}, nil},
		{"resolve usage", []string{"resolve"}, nil},
		{"resolve starter missing", []string{"resolve", "--token", "tok"}, func(d *Deps) { d.NewStarter = nil }},
		{"resolve starter", []string{"resolve", "--token", "tok"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return nil, errors.New("starter") }
		}},
		{"resolve ensure", []string{"resolve", "--token", "tok"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return fakeSessionStarter{ensureErr: errors.New("ensure")}, nil }
		}},
		{"resolve renderer", []string{"resolve", "--token", "tok"}, func(d *Deps) { d.RenderJSONOrHuman = nil }},
		{"resolve result renderer", []string{"resolve", "--token", "tok"}, func(d *Deps) { d.RenderSessionResolveResult = nil }},
		{"revoke parse", []string{"revoke", "--bad"}, nil},
		{"revoke both", []string{"revoke", "--token", "tok", "--all"}, nil},
		{"revoke usage", []string{"revoke"}, nil},
		{"revoke starter missing", []string{"revoke", "--token", "tok"}, func(d *Deps) { d.NewStarter = nil }},
		{"revoke starter", []string{"revoke", "--token", "tok"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return nil, errors.New("starter") }
		}},
		{"revoke ensure", []string{"revoke", "--token", "tok"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return fakeSessionStarter{ensureErr: errors.New("ensure")}, nil }
		}},
		{"revoke renderer", []string{"revoke", "--token", "tok"}, func(d *Deps) { d.RenderJSONOrHuman = nil }},
		{"revoke action renderer", []string{"revoke", "--token", "tok"}, func(d *Deps) { d.RenderSimpleAction = nil }},
		{"list parse", []string{"list", "--bad"}, nil},
		{"list usage", []string{"list", "extra"}, nil},
		{"list starter missing", []string{"list"}, func(d *Deps) { d.NewStarter = nil }},
		{"list starter", []string{"list"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return nil, errors.New("starter") }
		}},
		{"list ensure", []string{"list"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return fakeSessionStarter{ensureErr: errors.New("ensure")}, nil }
		}},
		{"list local fallback", []string{"list", "--mine"}, func(d *Deps) {
			d.DefaultLocalDeps = nil
		}},
		{"list local user", []string{"list", "--mine"}, func(d *Deps) {
			d.DefaultLocalDeps = func() LocalDeps {
				return LocalDeps{LocalUser: func() (string, error) { return "", errors.New("user") }}
			}
		}},
		{"list renderer", []string{"list"}, func(d *Deps) { d.RenderJSONOrHuman = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := base
			if tc.mut != nil {
				tc.mut(&deps)
			}
			if err := SessionCommand(ctx, deps, tc.args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
				t.Fatalf("expected error for %v", tc.args)
			}
		})
	}
}

func TestSessionRPCErrorBranches(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		args []string
		fake fakeSessionRPC
	}{
		{"open rpc", []string{"open"}, fakeSessionRPC{openErr: errors.New("open")}},
		{"grant resolve", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal"}, fakeSessionRPC{resolveErr: errors.New("resolve")}},
		{"grant unsafe", []string{"grant-plaintext", "--token", "tok", "--item", "A", "--action", "reveal"}, fakeSessionRPC{agentSafe: false}},
		{"mutation resolve", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, fakeSessionRPC{resolveErr: errors.New("resolve")}},
		{"mutation unsafe", []string{"grant-mutation", "--token", "tok", "--item", "A", "--action", "expose"}, fakeSessionRPC{agentSafe: false}},
		{"resolve rpc", []string{"resolve", "--token", "tok"}, fakeSessionRPC{resolveErr: errors.New("resolve")}},
		{"revoke token rpc", []string{"revoke", "--token", "tok"}, fakeSessionRPC{revokeErr: errors.New("revoke")}},
		{"revoke token false", []string{"revoke", "--token", "tok"}, fakeSessionRPC{revokeSessionOK: false}},
		{"revoke all rpc", []string{"revoke", "--all"}, fakeSessionRPC{revokeAllErr: errors.New("all")}},
		{"list rpc", []string{"list"}, fakeSessionRPC{statusErr: errors.New("status")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := tc.fake
			deps := fullSessionDeps(t, &fake)
			if tc.name == "grant unsafe" || tc.name == "mutation unsafe" {
				fake.agentSafe = false
			}
			if tc.name == "revoke token false" {
				fake.revokeSessionOK = false
			}
			if err := SessionCommand(ctx, deps, tc.args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSessionAdditionalCommandBranches(t *testing.T) {
	ctx := context.Background()
	deps := fullSessionDeps(t, &fakeSessionRPC{})
	deps.DefaultLocalDeps = nil
	if err := SessionCommand(ctx, deps, []string{"grant-plaintext", "--token", "tok", "--item", "ALPHA", "--action", "reveal"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected default local deps error")
	}
	if err := SessionCommand(ctx, deps, []string{"grant-mutation", "--token", "tok", "--item", "ALPHA", "--action", "expose"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected default mutation local deps error")
	}

	deps = fullSessionDeps(t, &fakeSessionRPC{})
	deps.GlobalColorOptions = nil
	if err := SessionCommand(ctx, deps, []string{"list"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("list default color options: %v", err)
	}

	deps = fullSessionDeps(t, &fakeSessionRPC{})
	deps.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
	if err := SessionCommand(ctx, deps, []string{"revoke", "--all"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("revoke all ignores open-vault errors: %v", err)
	}

	deps = fullSessionDeps(t, &fakeSessionRPC{})
	deps.GrantOps = func() vaultops.GrantOpsDeps {
		return vaultops.GrantOpsDeps{
			RevokeAllGrants: func(*store.Handle) (int, error) { return 0, errors.New("revoke grants") },
		}
	}
	if err := SessionCommand(ctx, deps, []string{"revoke", "--all"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected revoke all grant error")
	}
}

func TestSessionFallbacksAndRenderHelpers(t *testing.T) {
	if label, value := cliPair("A", "B")[0], cliPair("A", "B")[1]; label != "A" || value != "B" {
		t.Fatal("bad cliPair")
	}
	now := time.Now()
	if got := sessionStateBadge(runtime.SessionView{ExpiresAt: now.Add(time.Minute)}, now, ui.ColorOptions{}); !strings.Contains(got, "active") {
		t.Fatalf("active badge %q", got)
	}
	if got := sessionStateBadge(runtime.SessionView{ExpiresAt: now.Add(-time.Minute)}, now, ui.ColorOptions{}); !strings.Contains(got, "expired") {
		t.Fatalf("expired badge %q", got)
	}
	var out bytes.Buffer
	if err := renderSessionListWithColor(&out, nil, ui.ColorOptions{}); err != nil || !strings.Contains(out.String(), "No active sessions") {
		t.Fatalf("empty list out=%q err=%v", out.String(), err)
	}
	out.Reset()
	if err := renderSessionListWithColor(&out, []runtime.SessionView{{ID: "sid", HostLabel: "h", ProjectRoot: "/r", LastSeenAt: now, ExpiresAt: now.Add(time.Minute)}}, ui.ColorOptions{}); err != nil {
		t.Fatalf("list render: %v", err)
	}
	if !strings.Contains(out.String(), "-") {
		t.Fatalf("consumer fallback missing in %q", out.String())
	}
	out.Reset()
	if err := renderSessionListWithColor(&out, []runtime.SessionView{{ID: "sid", HostLabel: "h", ProjectRoot: "/r", LastSeenAt: now, ExpiresAt: now.Add(time.Minute)}}, ui.ColorOptions{Verbose: true}); err != nil {
		t.Fatalf("verbose list render: %v", err)
	}
	if !strings.Contains(out.String(), "-") {
		t.Fatalf("user fallback missing in %q", out.String())
	}
	if err := renderSessionListWithColor(errorWriter{}, nil, ui.ColorOptions{}); err == nil {
		t.Fatal("expected empty list write error")
	}

	ld := defaultLocalDepsFallback()
	if err := ld.Approve(runtime.SessionView{}, "A", store.PlaintextReveal); err == nil {
		t.Fatal("expected fallback approve error")
	}
	if _, err := ld.UseGrant(&store.Handle{}, "tok", "A", store.PlaintextReveal, time.Second); err == nil {
		t.Fatal("expected fallback use grant error")
	}
	if _, err := ld.UseMutationGrant(&store.Handle{}, "binding", "tok", "A", store.SecretMutationExpose, time.Second); err == nil {
		t.Fatal("expected fallback use mutation grant error")
	}
	if _, err := ld.LocalUser(); err == nil {
		t.Fatal("expected fallback local user error")
	}
	if deps := defaultConfirmPlaintextGrantDepsFallback(); deps.GOOS != "linux" || deps.Command != nil || deps.UnderTest == nil || !deps.UnderTest() {
		t.Fatalf("bad confirm fallback: %+v", deps)
	}
	if got := resolveGrantOps(Deps{GrantOps: func() vaultops.GrantOpsDeps { return vaultops.GrantOpsDeps{} }}); got.RevokeAllGrants != nil {
		t.Fatal("expected custom zero grant ops")
	}
	got := resolveGrantOps(Deps{})
	if got.RevokeAllGrants == nil || got.DisableConvenienceUnlock == nil {
		t.Fatal("expected default grant ops")
	}
	func() {
		defer func() { _ = recover() }()
		_, _ = got.DisableConvenienceUnlock(&store.Handle{}, context.Background())
	}()
}

func TestConfirmPlaintextGrantBranches(t *testing.T) {
	session := runtime.SessionView{HostLabel: "agent"}
	if err := ConfirmPlaintextGrant(Deps{}, session, "ALPHA", store.PlaintextReveal); err != nil {
		t.Fatalf("default under-test confirm: %v", err)
	}
	if err := ConfirmPlaintextGrant(Deps{DefaultConfirmPlaintextGrantDeps: func() ConfirmPlaintextGrantDeps {
		return ConfirmPlaintextGrantDeps{UnderTest: func() bool { return true }}
	}}, session, "ALPHA", store.PlaintextReveal); err != nil {
		t.Fatalf("custom under-test confirm: %v", err)
	}
	origStdin := os.Stdin
	regularStdin, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = regularStdin
	if err := ConfirmPlaintextGrantWithDeps(session, "ALPHA", store.PlaintextReveal, ConfirmPlaintextGrantDeps{
		GOOS:      "linux",
		UnderTest: func() bool { return false },
	}); err == nil {
		t.Fatal("expected non-interactive linux confirmation error")
	}
	os.Stdin = origStdin
	if err := ConfirmPlaintextGrantWithDeps(session, "ALPHA", store.PlaintextReveal, ConfirmPlaintextGrantDeps{
		GOOS:      "darwin",
		UnderTest: func() bool { return false },
	}); err == nil {
		t.Fatal("expected missing command error")
	}
	if err := ConfirmPlaintextGrantWithDeps(session, "ALPHA", store.PlaintextReveal, ConfirmPlaintextGrantDeps{
		GOOS:      "darwin",
		UnderTest: func() bool { return false },
		Command:   func(string, ...string) *exec.Cmd { return exec.Command("sh", "-c", "exit 0") },
	}); err != nil {
		t.Fatalf("darwin approve: %v", err)
	}
	if err := ConfirmPlaintextGrantWithDeps(session, "ALPHA", store.PlaintextReveal, ConfirmPlaintextGrantDeps{
		GOOS:      "darwin",
		UnderTest: func() bool { return false },
		Command:   func(string, ...string) *exec.Cmd { return exec.Command("sh", "-c", "exit 1") },
	}); err == nil {
		t.Fatal("expected darwin cancel")
	}

	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("pty unavailable: %v", err)
	}
	defer master.Close()
	defer slave.Close()
	outFile, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := outFile.Close(); err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdin = slave
	os.Stdout = outFile
	t.Cleanup(func() {
		os.Stdin = origStdin
		os.Stdout = origStdout
	})
	if err := ConfirmPlaintextGrantWithDeps(runtime.SessionView{HostLabel: "agent", ProjectRoot: "/repo"}, "ALPHA", store.PlaintextReveal, ConfirmPlaintextGrantDeps{
		GOOS:      "linux",
		UnderTest: func() bool { return false },
	}); err == nil {
		t.Fatal("expected stdout write error")
	}

	outFile2, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = outFile2
	origReadString := confirmPlaintextGrantReadString
	confirmPlaintextGrantReadString = func(*bufio.Reader, byte) (string, error) {
		return "", errors.New("read")
	}
	t.Cleanup(func() { confirmPlaintextGrantReadString = origReadString })
	if err := ConfirmPlaintextGrantWithDeps(runtime.SessionView{HostLabel: "agent", ProjectRoot: "/repo"}, "ALPHA", store.PlaintextReveal, ConfirmPlaintextGrantDeps{
		GOOS:      "linux",
		UnderTest: func() bool { return false },
	}); err == nil {
		t.Fatal("expected stdin read error")
	}
}

func TestConfirmPlaintextGrantTerminalApprove(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("pty unavailable: %v", err)
	}
	defer master.Close()
	defer slave.Close()
	origStdin := os.Stdin
	origStdout := os.Stdout
	outFile, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatal(err)
	}
	defer outFile.Close()
	os.Stdin = slave
	os.Stdout = outFile
	t.Cleanup(func() {
		os.Stdin = origStdin
		os.Stdout = origStdout
	})
	go func() {
		_, _ = master.Write([]byte("grant reveal ALPHA\n"))
	}()
	err = ConfirmPlaintextGrantWithDeps(runtime.SessionView{HostLabel: "agent", ProjectRoot: "/repo"}, "ALPHA", store.PlaintextReveal, ConfirmPlaintextGrantDeps{
		GOOS:      "linux",
		UnderTest: func() bool { return false },
	})
	if err != nil {
		t.Fatalf("terminal approval: %v", err)
	}
	go func() {
		_, _ = master.Write([]byte("no\n"))
	}()
	err = ConfirmPlaintextGrantWithDeps(runtime.SessionView{HostLabel: "agent", ProjectRoot: "/repo"}, "ALPHA", store.PlaintextReveal, ConfirmPlaintextGrantDeps{
		GOOS:      "linux",
		UnderTest: func() bool { return false },
	})
	if err == nil {
		t.Fatal("expected terminal cancellation")
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write") }
