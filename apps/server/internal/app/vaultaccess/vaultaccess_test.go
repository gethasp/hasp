package vaultaccess

import (
	"context"
	"errors"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestWrappersDelegateToRegisteredFunctions(t *testing.T) {
	origOpen := OpenVaultFn
	origCanonical := CanonicalProjectRootFn
	origBinding := ResolveBindingViewFn
	t.Cleanup(func() {
		OpenVaultFn = origOpen
		CanonicalProjectRootFn = origCanonical
		ResolveBindingViewFn = origBinding
	})

	wantErr := errors.New("open")
	OpenVaultFn = func(context.Context) (*store.Handle, error) { return nil, wantErr }
	if _, err := OpenVault(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("OpenVault err=%v", err)
	}

	CanonicalProjectRootFn = func(_ context.Context, projectPath string) (string, error) {
		if projectPath != "." {
			t.Fatalf("unexpected project path %q", projectPath)
		}
		return "/repo", nil
	}
	if got, err := CanonicalProjectRoot(context.Background(), "."); err != nil || got != "/repo" {
		t.Fatalf("CanonicalProjectRoot = %q err=%v", got, err)
	}

	ResolveBindingViewFn = func(_ *store.Handle, _ context.Context, projectPath string) (store.Binding, []store.VisibleReference, error) {
		if projectPath != "/repo" {
			t.Fatalf("unexpected binding path %q", projectPath)
		}
		return store.Binding{ID: "binding"}, []store.VisibleReference{{Alias: "secret_01"}}, nil
	}
	binding, visible, err := ResolveBindingView(nil, context.Background(), "/repo")
	if err != nil || binding.ID != "binding" || len(visible) != 1 {
		t.Fatalf("ResolveBindingView binding=%+v visible=%+v err=%v", binding, visible, err)
	}
}
