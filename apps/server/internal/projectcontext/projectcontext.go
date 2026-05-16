package projectcontext

import (
	"context"
	"fmt"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

type Defaults struct {
	AutoProtectRepos bool
	AutoInstallHooks bool
	DefaultPolicy    store.SecretPolicy
}

type ResolveBindingViewFunc func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error)
type UpsertBindingFunc func(*store.Handle, context.Context, string, map[string]string, store.SecretPolicy, bool) (store.Binding, error)

type Deps struct {
	ResolveBindingView ResolveBindingViewFunc
	LoadDefaults       func() (Defaults, error)
	CanonicalRoot      func(context.Context, string) (string, error)
	IsGitRepo          func(string) bool
	InstallHooks       func(string) error
	UpsertBinding      UpsertBindingFunc
}

func Ensure(ctx context.Context, handle *store.Handle, projectRoot string, deps Deps) (store.Binding, []store.VisibleReference, bool, error) {
	binding, visible, err := deps.ResolveBindingView(handle, ctx, projectRoot)
	if err != nil {
		return store.Binding{}, nil, false, err
	}
	if binding.ID != "" {
		return binding, visible, false, nil
	}

	defaults, err := deps.LoadDefaults()
	if err != nil {
		return store.Binding{}, nil, false, err
	}
	if !defaults.AutoProtectRepos {
		return binding, visible, false, nil
	}

	root, err := deps.CanonicalRoot(ctx, projectRoot)
	if err != nil {
		return store.Binding{}, nil, false, err
	}
	if !deps.IsGitRepo(root) {
		return binding, visible, false, nil
	}
	if _, err := Bind(ctx, handle, root, binding.Aliases, defaults.DefaultPolicy, defaults.AutoInstallHooks, deps); err != nil {
		return store.Binding{}, nil, false, err
	}
	binding, visible, err = deps.ResolveBindingView(handle, ctx, root)
	return binding, visible, true, err
}

func EnsureExplicit(ctx context.Context, handle *store.Handle, projectRoot string, deps Deps) (store.Binding, []store.VisibleReference, bool, error) {
	binding, visible, err := deps.ResolveBindingView(handle, ctx, projectRoot)
	if err != nil {
		return store.Binding{}, nil, false, err
	}
	if binding.ID != "" {
		return binding, visible, false, nil
	}

	defaults, err := deps.LoadDefaults()
	if err != nil {
		return store.Binding{}, nil, false, err
	}
	root, err := deps.CanonicalRoot(ctx, projectRoot)
	if err != nil {
		return store.Binding{}, nil, false, err
	}
	if !deps.IsGitRepo(root) {
		return store.Binding{}, nil, false, fmt.Errorf("project %q is not a git repo", projectRoot)
	}
	if _, err := Bind(ctx, handle, root, binding.Aliases, defaults.DefaultPolicy, defaults.AutoInstallHooks, deps); err != nil {
		return store.Binding{}, nil, false, err
	}
	binding, visible, err = deps.ResolveBindingView(handle, ctx, root)
	return binding, visible, true, err
}

func Bind(ctx context.Context, handle *store.Handle, projectRoot string, aliases map[string]string, defaultPolicy store.SecretPolicy, installHooks bool, deps Deps) (store.Binding, error) {
	root := strings.TrimSpace(projectRoot)
	if installHooks {
		if err := deps.InstallHooks(root); err != nil {
			return store.Binding{}, err
		}
	}
	return deps.UpsertBinding(handle, ctx, root, CloneAliases(aliases), defaultPolicy, installHooks)
}

func CloneAliases(input map[string]string) map[string]string {
	if len(input) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}
