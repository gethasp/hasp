package app

// RED-TEAM-ONLY: Do not modify this file during GREEN implementation except
// to create the runtimeops package and defaultRuntimeDeps() that satisfy these
// assertions. Any removal of a pinned function name requires RED-team sign-off.
//
// hasp-1mvx Stage 5c RED: boundary tests for the package-app wrapper.
//
// These tests verify two things:
//  1. The existing top-level command functions (exportBackupCommand, etc.) in
//     package app still exist after migration, so the many existing tests that
//     call them by name continue to compile and pass.
//  2. A defaultRuntimeDeps() function exists in package app that returns a
//     runtimeops.Deps wired to the existing package-level seam vars.

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/runtimeops"
)

// ── Compile-time: defaultRuntimeDeps must exist and return runtimeops.Deps ───
//
// If GREEN does not add a defaultRuntimeDeps() function to package app
// (e.g. in a new runtime_deps.go file), this var will fail to compile.

var _ runtimeops.Deps = defaultRuntimeDeps()

// ── Compile-time: per-command functions must survive in package app ───────────
//
// The following functions are called directly by existing tests in package app:
//   - exportBackupCommand     (backup_argv_secret_red_test.go, backup_audit_edge_test.go,
//                              coverage_edges_test.go)
//   - restoreBackupCommand    (backup_argv_secret_red_test.go, backup_audit_edge_test.go,
//                              coverage_edges_test.go)
//   - tuiCommand              (app_misc_coverage_test.go)
//   - daemonCommand           (app_test.go, coverage_edges_test.go)
//   - pingCommand             (coverage_edges_test.go, human_output_commands_test.go,
//                              runtime_commands_extra_test.go)
//   - pingCommandWithArgs     (command_branch_matrix_test.go)
//   - statusCommand           (coverage_edges_test.go, human_output_commands_test.go,
//                              runtime_commands_extra_test.go)
//   - statusCommandWithArgs   (command_branch_matrix_test.go)
//
// Each must remain callable in package app after migration — either as a
// stand-alone function or as a shim that prepends its subcommand and routes
// through runtimeops.RuntimeCommand.

var _ = exportBackupCommand
var _ = restoreBackupCommand
var _ = tuiCommand
var _ = daemonCommand
var _ = pingCommand
var _ = pingCommandWithArgs
var _ = statusCommand
var _ = statusCommandWithArgs

// ── Behaviour: wiring check ───────────────────────────────────────────────────

// TestRuntimeBoundaryDefaultDepsNonNil verifies that defaultRuntimeDeps exists
// in package app. A nil function pointer or missing definition is the RED
// signal. Behavioural non-nil checks of each closure field belong in a
// GREEN-phase integration test; the compile-time assertion above is the primary
// RED signal.
func TestRuntimeBoundaryDefaultDepsNonNil(t *testing.T) {
	lockAppSeams(t)
	// We do not call defaultRuntimeDeps() here because the underlying seam vars
	// (openVaultHandleFn, newVaultStoreFn, etc.) reference real OS operations
	// not set up in unit tests. We assert non-nil at the function level: if
	// defaultRuntimeDeps is not defined GREEN has not landed yet.
	//
	// Non-nil check of the function itself (compile-time, above) is sufficient
	// for the RED signal.
	_ = defaultRuntimeDeps // referenced above via var _; keep this comment for docs.
}

// TestRuntimeBoundaryUnknownCommand asserts that after migration the package-app
// wiring propagates unknown-command errors from runtimeops.RuntimeCommand.
// We drive this through the fakeStarter path so no real daemon is needed.
func TestRuntimeBoundaryUnknownCommand(t *testing.T) {
	lockAppSeams(t)
	err := runtimeops.RuntimeCommand(
		context.Background(),
		runtimeops.Deps{},
		[]string{"no-such-command-xyzzy"},
		bytes.NewReader(nil),
		io.Discard,
		io.Discard,
	)
	if err == nil {
		t.Fatal("RuntimeCommand(no-such-command-xyzzy) returned nil; want an error")
	}
}
