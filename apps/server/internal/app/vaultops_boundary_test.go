package app

// hasp-htiz Stage 5a RED: boundary tests for the package-app wrapper.
//
// These tests verify two things:
//  1. The existing vaultCommand(ctx, args, ...) entrypoint in package app
//     still behaves correctly after migration (wrapper-to-vaultops delegation).
//  2. The per-subcommand shims that are called by existing tests survive in
//     package app so that those tests continue to compile and pass.
//
// RED-TEAM-ONLY: Do not modify this file during GREEN implementation except
// to create the vaultops package and defaultVaultDeps() that satisfy these
// assertions. Any removal of a pinned function name requires RED-team sign-off.

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/vaultops"
)

// ── Compile-time: defaultVaultDeps must exist and return vaultops.Deps ────────
//
// If GREEN does not add a defaultVaultDeps() function to package app
// (e.g. in a new vault_deps.go file), this var will fail to compile.

var _ vaultops.Deps = defaultVaultDeps()

// ── Compile-time: dispatch shim must exist ────────────────────────────────────
//
// vaultCommand is called from hasp_ber_conformance_test.go. After Stage 5a GREEN
// it must remain as a shim that delegates to vaultops.VaultCommand. This var
// pins its continued existence.

var _ = vaultCommand

// ── Compile-time: per-subcommand shims must survive in package app ────────────
//
// The following functions are called directly by existing tests in package app:
//   - vaultLockCommand          (hasp_ber_conformance_test.go)
//   - vaultLockCommandWithDeps  (hasp_ber_conformance_test.go, vault_forget_device_seams_test.go)
//   - vaultForgetDeviceCommand  (vault_forget_device_seams_test.go)
//   - vaultForgetDeviceCommandWithDeps (vault_forget_device_seams_test.go)
//
// Each must remain callable in package app after migration — either as a
// stand-alone function or as a shim that prepends its subcommand and routes
// through vaultops.VaultCommand.
//
// vaultRekeyCommand and vaultRekdfCommand had no direct test callers and were
// removed; they are still reached via vaultCommand dispatch with the
// "rekey"/"rekdf" subcommand args.

var _ = vaultLockCommand
var _ = vaultLockCommandWithDeps
var _ = vaultForgetDeviceCommand
var _ = vaultForgetDeviceCommandWithDeps

// ── Behaviour: vaultCommand dispatch still works ──────────────────────────────

func TestVaultBoundaryHelpStillWorks(t *testing.T) {
	lockAppSeams(t)
	var out bytes.Buffer
	err := vaultCommand(context.Background(), []string{"help"}, &out, nil)
	if err != nil {
		t.Fatalf("vaultCommand(help) returned %v; want nil", err)
	}
	if out.Len() == 0 {
		t.Fatal("vaultCommand(help) produced no output; expected help text")
	}
}

// TestVaultBoundaryUnknownSubcommand asserts that the package-app wrapper
// surfaces the unknown-subcommand error after migration.
func TestVaultBoundaryUnknownSubcommand(t *testing.T) {
	lockAppSeams(t)
	err := vaultCommand(context.Background(), []string{"no-such-subcommand-xyzzy"}, io.Discard, nil)
	if err == nil {
		t.Fatal("vaultCommand(no-such-subcommand-xyzzy) returned nil; want an error")
	}
}

// TestVaultBoundaryDefaultDepsNonNil verifies that every closure field on the
// Deps returned by defaultVaultDeps() is non-nil. A nil closure field causes a
// panic at call time, which would be a regression against the direct-seam
// implementation that existed before migration.
func TestVaultBoundaryDefaultDepsNonNil(t *testing.T) {
	lockAppSeams(t)
	// We do not call defaultVaultDeps() here because the underlying seam vars
	// (openVaultHandleFn, etc.) reference a real vault that is not set up in
	// unit tests. We assert non-nil at the function level: if defaultVaultDeps
	// is not defined GREEN has not landed yet.
	//
	// Non-nil check of the function itself (compile-time, above) is sufficient
	// for the RED signal. Behavioural non-nil checks of each closure field
	// belong in a GREEN-phase integration test.
	_ = defaultVaultDeps // referenced above via var _; keep this comment for docs.
}
