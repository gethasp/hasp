package vaultops

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
}

func (k *fakeKeyring) Set(_ context.Context, service string, account string, value string) error {
	if k.values == nil {
		k.values = map[string]string{}
	}
	k.values[service+"/"+account] = value
	return nil
}

func (k *fakeKeyring) Get(service string, account string) (string, error) {
	value, ok := k.values[service+"/"+account]
	if !ok {
		return "", store.ErrKeyringUnavailable
	}
	return value, nil
}

func (k *fakeKeyring) Delete(service string, account string) error {
	delete(k.values, service+"/"+account)
	return nil
}

type fakeVaultStarter struct {
	socketPath string
	connectErr error
}

func (s fakeVaultStarter) Connect(ctx context.Context) (*runtime.Client, error) {
	if s.connectErr != nil {
		return nil, s.connectErr
	}
	return runtime.Dial(ctx, s.socketPath)
}

type fakeVaultRPC struct {
	lockErr error
	revoked int
}

func (r *fakeVaultRPC) LockVault(_ runtime.LockVaultRequest, reply *runtime.LockVaultResponse) error {
	if r.lockErr != nil {
		return r.lockErr
	}
	*reply = runtime.LockVaultResponse{RevokedCount: r.revoked, Locked: true}
	return nil
}

func startVaultRPC(t *testing.T, fake *fakeVaultRPC) string {
	t.Helper()
	socket := filepath.Join(os.TempDir(), fmt.Sprintf("hasp-vaultops-%d-%d.sock", os.Getpid(), time.Now().UnixNano()))
	_ = os.Remove(socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := rpc.NewServer()
	if err := server.RegisterName("HASP", fake); err != nil {
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

func newVaultHandle(t *testing.T, home string) *store.Handle {
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
	return handle
}

func fullVaultDeps(t *testing.T, fake *fakeVaultRPC) Deps {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	handle := newVaultHandle(t, home)
	socket := startVaultRPC(t, fake)
	return Deps{
		OpenVaultHandle: func(context.Context) (*store.Handle, error) { return handle, nil },
		NewStarter:      func() (Starter, error) { return fakeVaultStarter{socketPath: socket}, nil },
		GrantOps: func() GrantOpsDeps {
			return GrantOpsDeps{
				RevokeAllGrants: func(*store.Handle) (int, error) { return 4, nil },
				DisableConvenienceUnlock: func(*store.Handle, context.Context) (bool, error) {
					return true, nil
				},
			}
		},
		LoadMasterPassword:    func() (string, error) { return "master-password", nil },
		LoadNewMasterPassword: func() (string, error) { return "new-master-password", nil },
		RenderJSONOrHuman: func(_ context.Context, stdout io.Writer, _ bool, _ any, human func(io.Writer) error) error {
			return human(stdout)
		},
		RenderSimpleAction: func(_ context.Context, out io.Writer, title string, lead string, pairs ...[2]string) error {
			_, err := fmt.Fprintf(out, "%s:%s", title, pairs[0][1])
			return err
		},
		GlobalJSON: func(context.Context) bool { return false },
	}
}

func TestVaultCommandSuccessPaths(t *testing.T) {
	ctx := context.Background()
	var out bytes.Buffer
	for _, args := range [][]string{
		{"lock"},
		{"forget-device"},
		{"rekey"},
		{"rekdf"},
		{"help"},
		nil,
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			deps := fullVaultDeps(t, &fakeVaultRPC{revoked: 2})
			out.Reset()
			if err := VaultCommand(ctx, deps, args, strings.NewReader(""), &out, io.Discard); err != nil {
				t.Fatalf("VaultCommand(%v): %v", args, err)
			}
		})
	}
}

func TestVaultCommandErrorBranches(t *testing.T) {
	ctx := context.Background()
	base := fullVaultDeps(t, &fakeVaultRPC{})
	cases := []struct {
		name string
		args []string
		mut  func(*Deps)
	}{
		{"unknown", []string{"wat"}, nil},
		{"lock parse", []string{"lock", "--bad"}, nil},
		{"lock usage", []string{"lock", "extra"}, nil},
		{"lock starter", []string{"lock"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return nil, errors.New("starter") }
		}},
		{"lock connect ignored", []string{"lock"}, func(d *Deps) {
			d.NewStarter = func() (Starter, error) { return fakeVaultStarter{connectErr: errors.New("connect")}, nil }
		}},
		{"lock rpc", []string{"lock"}, func(d *Deps) {
			socket := startVaultRPC(t, &fakeVaultRPC{lockErr: errors.New("lock")})
			d.NewStarter = func() (Starter, error) { return fakeVaultStarter{socketPath: socket}, nil }
		}},
		{"lock revoke grants", []string{"lock"}, func(d *Deps) {
			d.GrantOps = func() GrantOpsDeps {
				return GrantOpsDeps{
					RevokeAllGrants: func(*store.Handle) (int, error) { return 0, errors.New("revoke") },
					DisableConvenienceUnlock: func(*store.Handle, context.Context) (bool, error) {
						return false, nil
					},
				}
			}
		}},
		{"lock forget", []string{"lock"}, func(d *Deps) {
			d.GrantOps = func() GrantOpsDeps {
				return GrantOpsDeps{
					RevokeAllGrants: func(*store.Handle) (int, error) { return 0, nil },
					DisableConvenienceUnlock: func(*store.Handle, context.Context) (bool, error) {
						return false, errors.New("forget")
					},
				}
			}
		}},
		{"forget parse", []string{"forget-device", "--bad"}, nil},
		{"forget usage", []string{"forget-device", "extra"}, nil},
		{"forget open", []string{"forget-device"}, func(d *Deps) {
			d.OpenVaultHandle = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"forget disable", []string{"forget-device"}, func(d *Deps) {
			d.GrantOps = func() GrantOpsDeps {
				return GrantOpsDeps{DisableConvenienceUnlock: func(*store.Handle, context.Context) (bool, error) {
					return false, errors.New("disable")
				}}
			}
		}},
		{"rekey parse", []string{"rekey", "--bad"}, nil},
		{"rekey usage", []string{"rekey", "extra"}, nil},
		{"rekey load old", []string{"rekey"}, func(d *Deps) {
			d.LoadMasterPassword = func() (string, error) { return "", errors.New("old") }
		}},
		{"rekey load new", []string{"rekey"}, func(d *Deps) {
			d.LoadNewMasterPassword = func() (string, error) { return "", errors.New("new") }
		}},
		{"rekey open", []string{"rekey"}, func(d *Deps) {
			d.OpenVaultHandle = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"rekey bad password", []string{"rekey"}, func(d *Deps) {
			d.LoadMasterPassword = func() (string, error) { return "wrong", nil }
		}},
		{"rekdf parse", []string{"rekdf", "--bad"}, nil},
		{"rekdf usage", []string{"rekdf", "extra"}, nil},
		{"rekdf load", []string{"rekdf"}, func(d *Deps) {
			d.LoadMasterPassword = func() (string, error) { return "", errors.New("load") }
		}},
		{"rekdf open", []string{"rekdf"}, func(d *Deps) {
			d.OpenVaultHandle = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"rekdf bad password", []string{"rekdf"}, func(d *Deps) {
			d.LoadMasterPassword = func() (string, error) { return "wrong", nil }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := base
			if tc.mut != nil {
				tc.mut(&deps)
			}
			err := VaultCommand(ctx, deps, tc.args, strings.NewReader(""), io.Discard, io.Discard)
			if tc.name == "lock starter" || tc.name == "lock connect ignored" {
				if err != nil {
					t.Fatalf("expected ignored starter/connect error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error for %v", tc.args)
			}
		})
	}
}

func TestVaultFallbacks(t *testing.T) {
	ctx := context.Background()
	deps := fullVaultDeps(t, &fakeVaultRPC{})
	deps.IsHelpArg = nil
	deps.PrintHelpTopic = nil
	if err := VaultCommand(ctx, deps, []string{"-h"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("fallback help: %v", err)
	}
	if label, value := cliPair("A", "B")[0], cliPair("A", "B")[1]; label != "A" || value != "B" {
		t.Fatal("bad cliPair")
	}
	if got := resolveGrantOpsDeps(deps); got.RevokeAllGrants == nil {
		t.Fatal("expected custom grant ops")
	}
	got := resolveGrantOpsDeps(Deps{})
	if got.RevokeAllGrants == nil || got.DisableConvenienceUnlock == nil {
		t.Fatal("expected default grant ops")
	}
	func() {
		defer func() { _ = recover() }()
		_, _ = got.DisableConvenienceUnlock(&store.Handle{}, context.Background())
	}()
	deps = fullVaultDeps(t, &fakeVaultRPC{})
	deps.GrantOps = func() GrantOpsDeps {
		return GrantOpsDeps{
			RevokeAllGrants: func(*store.Handle) (int, error) { return 0, nil },
			DisableConvenienceUnlock: func(*store.Handle, context.Context) (bool, error) {
				return false, nil
			},
		}
	}
	var out bytes.Buffer
	if err := VaultCommand(ctx, deps, []string{"forget-device", "--json"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("forget already forgotten: %v", err)
	}
}
