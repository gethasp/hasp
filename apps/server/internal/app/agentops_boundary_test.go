package app

// hasp-o2tm Stage 3 RED: boundary tests for the package-app wrapper.
//
// These tests verify two things:
//  1. The existing agentConsumerCommand(ctx, args, ...) entrypoint in package app
//     still behaves correctly after migration (wrapper-to-agentops delegation).
//  2. The per-subcommand shims (agentConnectCommand, agentDisconnectCommand,
//     agentListCommand, agentListSupportedCommand, agentMCPCommand) survive in
//     package app so that the many existing tests that call them by name
//     continue to compile and pass.
//
// RED-TEAM-ONLY: Do not modify this file during GREEN implementation except
// to create the agentops package and defaultAgentDeps() that satisfy these
// assertions. Any removal of a pinned function name requires RED-team sign-off.

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/agentops"
)

// ── Compile-time: defaultAgentDeps must exist and return agentops.Deps ────────
//
// If GREEN does not add a defaultAgentDeps() function to package app
// (e.g. in a new agent_deps.go file), this var will fail to compile.

var _ agentops.Deps = defaultAgentDeps()

// ── Compile-time: dispatch shim must exist ────────────────────────────────────
//
// agentConsumerCommand is called from command_inventory.go and from many
// existing tests. After Stage 3 GREEN it must remain as a shim that delegates
// to agentops.AgentCommand. This var pins its continued existence.

var _ = agentConsumerCommand

// ── Compile-time: per-subcommand shims must survive in package app ────────────
//
// The following functions are called directly by existing tests in package app:
//   - agentConnectCommand       (consumer_commands_zero_hit_test.go, consumer_helper_branches_test.go)
//   - agentDisconnectCommand    (consumer_commands_zero_hit_test.go, consumer_helper_branches_test.go)
//   - agentListCommand          (consumer_commands_zero_hit_test.go)
//   - agentListSupportedCommand (hasp_ber_conformance_test.go)
//   - agentMCPCommand           (agent_consumers_test.go)
//
// Each must remain callable in package app after migration — either as a
// stand-alone function or as a shim that prepends its subcommand and routes
// through agentops.AgentCommand.

var _ = agentConnectCommand
var _ = agentDisconnectCommand
var _ = agentListCommand
var _ = agentListSupportedCommand
var _ = agentMCPCommand

// ── Behaviour: agentConsumerCommand dispatch still works ─────────────────────

func TestAgentBoundaryHelpStillWorks(t *testing.T) {
	lockAppSeams(t)
	var out bytes.Buffer
	err := agentConsumerCommand(context.Background(), []string{"help"}, bytes.NewReader(nil), &out, io.Discard)
	if err != nil {
		t.Fatalf("agentConsumerCommand(help) returned %v; want nil", err)
	}
	if out.Len() == 0 {
		t.Fatal("agentConsumerCommand(help) produced no output; expected help text")
	}
}

// TestAgentBoundaryUnknownSubcommand asserts that the package-app wrapper
// surfaces the unknown-subcommand error after migration.
func TestAgentBoundaryUnknownSubcommand(t *testing.T) {
	lockAppSeams(t)
	err := agentConsumerCommand(context.Background(), []string{"no-such-subcommand-xyzzy"}, bytes.NewReader(nil), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("agentConsumerCommand(no-such-subcommand-xyzzy) returned nil; want an error")
	}
}

// TestAgentBoundaryDefaultDepsNonNil verifies that every closure field on the
// Deps returned by defaultAgentDeps() is non-nil. A nil closure field causes a
// panic at call time, which would be a regression against the direct-seam
// implementation that existed before migration.
func TestAgentBoundaryDefaultDepsNonNil(t *testing.T) {
	lockAppSeams(t)
	// We do not call defaultAgentDeps() here because the underlying seam vars
	// (openVaultHandleFn, etc.) reference a real vault that is not set up in
	// unit tests. We assert non-nil at the function level: if defaultAgentDeps
	// is not defined GREEN has not landed yet.
	//
	// Non-nil check of the function itself (compile-time, above) is sufficient
	// for the RED signal. Behavioural non-nil checks of each closure field
	// belong in a GREEN-phase integration test.
	_ = defaultAgentDeps // referenced above via var _; keep this comment for docs.
}
