package projectcontext

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestEnsureReusesExistingBinding(t *testing.T) {
	deps := projectContextDeps(t)
	deps.ResolveBindingView = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{ID: "existing"}, []store.VisibleReference{{Alias: "secret_01"}}, nil
	}

	binding, visible, created, err := Ensure(context.Background(), nil, "/repo", deps)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if binding.ID != "existing" || created {
		t.Fatalf("binding=%+v created=%v, want existing false", binding, created)
	}
	if len(visible) != 1 || visible[0].Alias != "secret_01" {
		t.Fatalf("visible = %+v", visible)
	}
}

func TestEnsureAutoProtectsGitRepo(t *testing.T) {
	deps := projectContextDeps(t)
	calls := 0
	deps.ResolveBindingView = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		calls++
		if calls == 1 {
			return store.Binding{Aliases: map[string]string{"secret_01": "api_token"}}, nil, nil
		}
		return store.Binding{ID: "created"}, []store.VisibleReference{{Alias: "secret_01"}}, nil
	}

	binding, visible, created, err := Ensure(context.Background(), nil, " /repo ", deps)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if binding.ID != "created" || !created {
		t.Fatalf("binding=%+v created=%v, want created binding", binding, created)
	}
	if len(visible) != 1 {
		t.Fatalf("visible = %+v", visible)
	}
}

func TestEnsureSkipsWhenDefaultsDisableAutoProtect(t *testing.T) {
	deps := projectContextDeps(t)
	deps.LoadDefaults = func() (Defaults, error) {
		return Defaults{AutoProtectRepos: false}, nil
	}

	binding, _, created, err := Ensure(context.Background(), nil, "/repo", deps)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if binding.ID != "" || created {
		t.Fatalf("binding=%+v created=%v, want no creation", binding, created)
	}
}

func TestEnsureSkipsAutoProtectForNonGitRepo(t *testing.T) {
	deps := projectContextDeps(t)
	deps.IsGitRepo = func(string) bool { return false }

	binding, _, created, err := Ensure(context.Background(), nil, "/repo", deps)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if binding.ID != "" || created {
		t.Fatalf("binding=%+v created=%v, want no creation", binding, created)
	}
}

func TestEnsureReturnsDependencyErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Deps)
		call   func(Deps) error
	}{
		{
			name: "resolve",
			mutate: func(deps *Deps) {
				deps.ResolveBindingView = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
					return store.Binding{}, nil, errors.New("resolve failed")
				}
			},
			call: func(deps Deps) error {
				_, _, _, err := Ensure(context.Background(), nil, "/repo", deps)
				return err
			},
		},
		{
			name: "defaults",
			mutate: func(deps *Deps) {
				deps.LoadDefaults = func() (Defaults, error) { return Defaults{}, errors.New("defaults failed") }
			},
			call: func(deps Deps) error {
				_, _, _, err := Ensure(context.Background(), nil, "/repo", deps)
				return err
			},
		},
		{
			name: "canonical",
			mutate: func(deps *Deps) {
				deps.CanonicalRoot = func(context.Context, string) (string, error) { return "", errors.New("canonical failed") }
			},
			call: func(deps Deps) error {
				_, _, _, err := Ensure(context.Background(), nil, "/repo", deps)
				return err
			},
		},
		{
			name: "bind",
			mutate: func(deps *Deps) {
				deps.InstallHooks = func(string) error { return errors.New("hooks failed") }
			},
			call: func(deps Deps) error {
				_, _, _, err := Ensure(context.Background(), nil, "/repo", deps)
				return err
			},
		},
		{
			name: "explicit non git",
			mutate: func(deps *Deps) {
				deps.IsGitRepo = func(string) bool { return false }
			},
			call: func(deps Deps) error {
				_, _, _, err := EnsureExplicit(context.Background(), nil, "/repo", deps)
				return err
			},
		},
		{
			name: "explicit resolve",
			mutate: func(deps *Deps) {
				deps.ResolveBindingView = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
					return store.Binding{}, nil, errors.New("explicit resolve failed")
				}
			},
			call: func(deps Deps) error {
				_, _, _, err := EnsureExplicit(context.Background(), nil, "/repo", deps)
				return err
			},
		},
		{
			name: "explicit defaults",
			mutate: func(deps *Deps) {
				deps.LoadDefaults = func() (Defaults, error) { return Defaults{}, errors.New("explicit defaults failed") }
			},
			call: func(deps Deps) error {
				_, _, _, err := EnsureExplicit(context.Background(), nil, "/repo", deps)
				return err
			},
		},
		{
			name: "explicit canonical",
			mutate: func(deps *Deps) {
				deps.CanonicalRoot = func(context.Context, string) (string, error) { return "", errors.New("explicit canonical failed") }
			},
			call: func(deps Deps) error {
				_, _, _, err := EnsureExplicit(context.Background(), nil, "/repo", deps)
				return err
			},
		},
		{
			name: "explicit bind",
			mutate: func(deps *Deps) {
				deps.UpsertBinding = func(*store.Handle, context.Context, string, map[string]string, store.SecretPolicy, bool) (store.Binding, error) {
					return store.Binding{}, errors.New("explicit bind failed")
				}
			},
			call: func(deps Deps) error {
				_, _, _, err := EnsureExplicit(context.Background(), nil, "/repo", deps)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := projectContextDeps(t)
			tt.mutate(&deps)
			if err := tt.call(deps); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestEnsureExplicitReusesExistingBinding(t *testing.T) {
	deps := projectContextDeps(t)
	deps.ResolveBindingView = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{ID: "existing"}, []store.VisibleReference{{Alias: "secret_01"}}, nil
	}

	binding, visible, created, err := EnsureExplicit(context.Background(), nil, "/repo", deps)
	if err != nil {
		t.Fatalf("EnsureExplicit: %v", err)
	}
	if binding.ID != "existing" || created || len(visible) != 1 {
		t.Fatalf("binding=%+v visible=%+v created=%v", binding, visible, created)
	}
}

func TestEnsureExplicitCreatesBinding(t *testing.T) {
	deps := projectContextDeps(t)
	calls := 0
	deps.ResolveBindingView = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		calls++
		if calls == 1 {
			return store.Binding{Aliases: map[string]string{"secret_01": "api_token"}}, nil, nil
		}
		return store.Binding{ID: "explicit"}, []store.VisibleReference{{Alias: "secret_01"}}, nil
	}

	binding, _, created, err := EnsureExplicit(context.Background(), nil, "/repo", deps)
	if err != nil {
		t.Fatalf("EnsureExplicit: %v", err)
	}
	if binding.ID != "explicit" || !created {
		t.Fatalf("binding=%+v created=%v, want explicit creation", binding, created)
	}
}

func TestBindTrimsRootInstallsHooksAndClonesAliases(t *testing.T) {
	deps := projectContextDeps(t)
	aliases := map[string]string{"secret_01": "api_token"}
	var hookRoot string
	deps.InstallHooks = func(root string) error {
		hookRoot = root
		return nil
	}
	var upsertAliases map[string]string
	deps.UpsertBinding = func(_ *store.Handle, _ context.Context, root string, aliases map[string]string, policy store.SecretPolicy, hooks bool) (store.Binding, error) {
		if root != "/repo" || policy != store.PolicySession || !hooks {
			t.Fatalf("upsert root=%q policy=%q hooks=%v", root, policy, hooks)
		}
		upsertAliases = aliases
		return store.Binding{ID: "bound"}, nil
	}

	binding, err := Bind(context.Background(), nil, " /repo ", aliases, store.PolicySession, true, deps)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if binding.ID != "bound" || hookRoot != "/repo" {
		t.Fatalf("binding=%+v hookRoot=%q", binding, hookRoot)
	}
	aliases["secret_01"] = "changed"
	if !reflect.DeepEqual(upsertAliases, map[string]string{"secret_01": "api_token"}) {
		t.Fatalf("aliases were not cloned: %#v", upsertAliases)
	}
	if got := CloneAliases(nil); len(got) != 0 {
		t.Fatalf("empty clone = %#v", got)
	}
}

func projectContextDeps(t *testing.T) Deps {
	t.Helper()
	return Deps{
		ResolveBindingView: func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
			return store.Binding{}, nil, nil
		},
		LoadDefaults: func() (Defaults, error) {
			return Defaults{AutoProtectRepos: true, AutoInstallHooks: true, DefaultPolicy: store.PolicySession}, nil
		},
		CanonicalRoot: func(_ context.Context, root string) (string, error) {
			if root == "bad" {
				return "", errors.New("bad root")
			}
			return "/repo", nil
		},
		IsGitRepo: func(string) bool { return true },
		InstallHooks: func(string) error {
			return nil
		},
		UpsertBinding: func(*store.Handle, context.Context, string, map[string]string, store.SecretPolicy, bool) (store.Binding, error) {
			return store.Binding{ID: "created"}, nil
		},
	}
}
