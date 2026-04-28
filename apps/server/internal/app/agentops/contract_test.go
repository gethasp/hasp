package agentops_test

// hasp-o2tm Stage 3 RED: contract tests for agentops.
//
// These tests FAIL on main because AgentCommand and Deps do not exist yet.
// They will PASS after the GREEN team lands internal/app/agentops/.
//
// The compile-time assertion at the top of the file is the primary RED
// signal: the file will not compile until the package exposes the exact
// symbols and signature required.
//
// RED-TEAM-ONLY: Do not modify this file during GREEN implementation except
// to create the package that satisfies the pinned contract. Any weakening
// of the pinned field list or function signature requires explicit RED-team
// sign-off.

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/agentops"
)

// ── Compile-time signature contract ──────────────────────────────────────────
//
// If agentops.AgentCommand does not exist, or has a different signature,
// this var declaration will produce a compile error — intentionally RED.

var _ func(ctx context.Context, deps agentops.Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error = agentops.AgentCommand

// ── Deps field contract ───────────────────────────────────────────────────────
//
// These are the 14 seam closure fields that correspond to the package-level
// vars in agent_consumers.go. Each must become a named field on agentops.Deps.
// Field names map to seam vars as follows:
//
//	storeGetAgentFn             → StoreGetAgent
//	storeListAgentsFn           → StoreListAgents
//	storeUpsertAgentFn          → StoreUpsertAgent
//	storeDeleteAgentFn          → StoreDeleteAgent
//	removeAgentConsumerConfigFn → RemoveAgentConsumerConfig
//	agentAtomicWriteFn          → AgentAtomicWrite
//	agentUserShellFn            → AgentUserShell
//	agentExecCommandContextFn   → AgentExecCommandContext
//	agentNewStarterFn           → AgentNewStarter
//	agentBuildExecutionEnvFn    → AgentBuildExecutionEnv
//	agentRegisterProcessFn      → AgentRegisterProcess
//	agentServeMCPFn             → AgentServeMCP
//	agentLoadSupportStatusesFn  → AgentLoadSupportStatuses
//	agentOpenSessionFn          → AgentOpenSession

func TestDepsHasRequiredFields(t *testing.T) {
	required := []string{
		"StoreGetAgent",
		"StoreListAgents",
		"StoreUpsertAgent",
		"StoreDeleteAgent",
		"RemoveAgentConsumerConfig",
		"AgentAtomicWrite",
		"AgentUserShell",
		"AgentExecCommandContext",
		"AgentNewStarter",
		"AgentBuildExecutionEnv",
		"AgentRegisterProcess",
		"AgentServeMCP",
		"AgentLoadSupportStatuses",
		"AgentOpenSession",
	}
	typ := reflect.TypeOf(agentops.Deps{})
	for _, name := range required {
		_, ok := typ.FieldByName(name)
		if !ok {
			t.Errorf("agentops.Deps is missing required field %q — GREEN team must add it", name)
		}
	}
}

// TestDepsFieldsAreClosures verifies that the required fields are all function
// types (closures), not plain values. A non-func field would indicate a
// structural mistake in the Deps definition.
func TestDepsFieldsAreClosures(t *testing.T) {
	funcFields := []string{
		"StoreGetAgent",
		"StoreListAgents",
		"StoreUpsertAgent",
		"StoreDeleteAgent",
		"RemoveAgentConsumerConfig",
		"AgentAtomicWrite",
		"AgentUserShell",
		"AgentExecCommandContext",
		"AgentNewStarter",
		"AgentBuildExecutionEnv",
		"AgentRegisterProcess",
		"AgentServeMCP",
		"AgentLoadSupportStatuses",
		"AgentOpenSession",
	}
	typ := reflect.TypeOf(agentops.Deps{})
	for _, name := range funcFields {
		f, ok := typ.FieldByName(name)
		if !ok {
			// Already caught by TestDepsHasRequiredFields; skip here.
			continue
		}
		if f.Type.Kind() != reflect.Func {
			t.Errorf("agentops.Deps.%s has kind %s; want func", name, f.Type.Kind())
		}
	}
}

// ── Behaviour: help ───────────────────────────────────────────────────────────

func TestAgentCommandHelp(t *testing.T) {
	var out bytes.Buffer
	err := agentops.AgentCommand(context.Background(), agentops.Deps{}, []string{"help"}, strings.NewReader(""), &out, io.Discard)
	if err != nil {
		t.Fatalf("AgentCommand(help) returned error %v; want nil", err)
	}
	if out.Len() == 0 {
		t.Fatal("AgentCommand(help) wrote nothing to stdout; expected agent help text")
	}
}

// ── Behaviour: unknown subcommand ─────────────────────────────────────────────

func TestAgentCommandUnknownSubcommand(t *testing.T) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := agentops.AgentCommand(context.Background(), agentops.Deps{}, []string{"unknown-subcommand-xyzzy"}, strings.NewReader(""), &out, &errOut)
	if err == nil {
		t.Fatal("AgentCommand(unknown-subcommand-xyzzy) returned nil; want an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown agent subcommand") {
		t.Errorf("error message %q does not contain 'unknown agent subcommand'", msg)
	}
}

// ── Behaviour: every known subcommand is reachable via --help ─────────────────
//
// For each subcommand, call AgentCommand(ctx, deps, [name, "--help"], ...).
// Acceptable outcomes:
//
//	a) returns nil and writes non-empty help text, OR
//	b) returns any non-nil error (parse fail is fine as long as no panic).
//
// A panic is the only unacceptable outcome.
func TestAgentCommandSubcommandsReachable(t *testing.T) {
	subcommands := []string{
		"connect", "disconnect", "list", "list-supported", "mcp",
	}
	for _, sub := range subcommands {
		t.Run(sub, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("AgentCommand(%q --help) panicked: %v", sub, r)
				}
			}()
			var out bytes.Buffer
			agentops.AgentCommand(context.Background(), agentops.Deps{}, []string{sub, "--help"}, strings.NewReader(""), &out, io.Discard) //nolint:errcheck
			// We do not fail on error — parse-fail is acceptable.
			// We only verify no panic (via recover above).
		})
	}
}
