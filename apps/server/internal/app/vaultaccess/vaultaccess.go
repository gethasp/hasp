// Package vaultaccess centralises the vault-open / project-root /
// binding-resolution helpers that the secret CLI surfaces and other
// app-internal subpackages need. Without this seam the soon-to-move
// secret handlers in internal/app/secretops/ would have to reach back
// into package app, which package app must in turn import for the
// dispatch entrypoint — the classic import cycle.
//
// Pattern: vaultaccess exports function-typed vars (OpenVaultFn,
// CanonicalProjectRootFn, ResolveBindingViewFn). Package app registers
// concrete closures via init() that read its existing seam variables
// dynamically, so test overrides of those originals (openVaultHandleFn,
// appCanonicalProjectRootFn, resolveBindingViewAppFn) continue to flow
// through transparently. Same approach as internal/app/auditlog/
// (hasp-tpsi). hasp-da2w (Stage 2e of hasp-mgz5).
package vaultaccess

import (
	"context"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// Function-typed seams. Package app installs concrete implementations
// in its init(); calling these before registration panics.
var (
	OpenVaultFn            func(ctx context.Context) (*store.Handle, error)
	CanonicalProjectRootFn func(ctx context.Context, projectPath string) (string, error)
	ResolveBindingViewFn   func(handle *store.Handle, ctx context.Context, projectPath string) (store.Binding, []store.VisibleReference, error)
)

// OpenVault opens a vault handle through the registered seam. Audit
// HMAC key installation happens inside the underlying app.openVaultHandle
// implementation so callers do not need to coordinate that themselves.
func OpenVault(ctx context.Context) (*store.Handle, error) {
	return OpenVaultFn(ctx)
}

// CanonicalProjectRoot resolves projectPath to its canonical form
// (typically the git top-level) through the registered seam.
func CanonicalProjectRoot(ctx context.Context, projectPath string) (string, error) {
	return CanonicalProjectRootFn(ctx, projectPath)
}

// ResolveBindingView returns the binding view for projectPath through
// the registered seam.
func ResolveBindingView(handle *store.Handle, ctx context.Context, projectPath string) (store.Binding, []store.VisibleReference, error) {
	return ResolveBindingViewFn(handle, ctx, projectPath)
}
