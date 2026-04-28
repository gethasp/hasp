package app

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/app/agentops"
	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/mcp"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/profiles"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// ── Seam vars (preserved for test overrides) ─────────────────────────────────

var (
	storeGetAgentFn             = (*store.Handle).GetAgentConsumer
	storeListAgentsFn           = (*store.Handle).ListAgentConsumers
	storeUpsertAgentFn          = (*store.Handle).UpsertAgentConsumer
	storeDeleteAgentFn          = (*store.Handle).DeleteAgentConsumer
	removeAgentConsumerConfigFn = removeAgentConsumerConfig
	agentAtomicWriteFn          = setupAtomicWrite
	agentUserShellFn            = func() string { return os.Getenv("SHELL") }
	agentExecCommandContextFn   = exec.CommandContext
	agentNewStarterFn           = func() (starter, error) { return newRuntimeStarterFn() }
	agentBuildExecutionEnvFn    = buildAgentExecutionEnv
	agentRegisterProcessFn      = registerProtectedProcess
	agentServeMCPFn             = mcp.Serve
	agentLoadSupportStatusesFn  = profiles.LoadSupportStatuses
	agentOpenSessionFn          = func(ctx context.Context, client *runtime.Client, hostLabel string, consumer store.AgentConsumer) (runtime.OpenSessionResponse, error) {
		return client.OpenSession(ctx, runtime.OpenSessionRequest{
			HostLabel:    hostLabel,
			ProjectRoot:  consumer.ProjectRoot,
			TTLSeconds:   int(runtime.DefaultSessionTTL.Seconds()),
			AgentSafe:    true,
			ConsumerName: consumer.Name,
		})
	}
)

// ── Dispatch shim ─────────────────────────────────────────────────────────────

// agentConsumerCommand is the root dispatcher for `hasp agent`. It delegates
// to agentops.AgentCommand using the seam-wired Deps from defaultAgentDeps().
func agentConsumerCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return agentops.AgentCommand(ctx, defaultAgentDeps(), args, stdin, stdout, stderr)
}

// ── Per-subcommand shims ──────────────────────────────────────────────────────
//
// These shims keep the package-app function signatures intact so that existing
// tests (which call them directly by name) continue to compile and pass.
// Each shim prepends its subcommand name and delegates to agentops.AgentCommand,
// which routes through the same seam vars via defaultAgentDeps().

func agentConnectCommand(ctx context.Context, args []string, stdout io.Writer) error {
	return agentops.AgentCommand(ctx, defaultAgentDeps(), append([]string{"connect"}, args...), nil, stdout, io.Discard)
}

func agentDisconnectCommand(ctx context.Context, args []string, stdout io.Writer) error {
	return agentops.AgentCommand(ctx, defaultAgentDeps(), append([]string{"disconnect"}, args...), nil, stdout, io.Discard)
}

func agentListCommand(ctx context.Context, args []string, stdout io.Writer) error {
	return agentops.AgentCommand(ctx, defaultAgentDeps(), append([]string{"list"}, args...), nil, stdout, io.Discard)
}

func agentListSupportedCommand(ctx context.Context, args []string, stdout io.Writer) error {
	return agentops.AgentCommand(ctx, defaultAgentDeps(), append([]string{"list-supported"}, args...), nil, stdout, io.Discard)
}

func agentMCPCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	return agentops.AgentCommand(ctx, defaultAgentDeps(), append([]string{"mcp"}, args...), stdin, stdout, io.Discard)
}

func agentLaunchCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, shellMode bool) error {
	subcommand := "launch"
	if shellMode {
		subcommand = "shell"
	}
	return agentops.AgentCommand(ctx, defaultAgentDeps(), append([]string{subcommand}, args...), stdin, stdout, stderr)
}

// ── Package-app helpers preserved for test compatibility ─────────────────────
//
// The following functions are called directly from existing tests in package app.
// They keep their original signatures and implementations.

// buildAgentExecutionEnv builds the environment variable slice for an agent
// process. Kept in package app (not moved to agentops) because existing tests
// call it directly using the package-private starter interface.
func buildAgentExecutionEnv(ctx context.Context, handle *store.Handle, consumer store.AgentConsumer, s starter, hostLabel string) ([]string, error) {
	resolved, err := appResolvePathsFn()
	if err != nil {
		return nil, err
	}
	env := []string{
		paths.EnvHome + "=" + resolved.HomeDir,
		secrettypes.EnvAgentSafeMode + "=1",
		secrettypes.EnvAgentConsumer + "=" + consumer.Name,
	}
	if consumer.ProjectRoot != "" {
		if _, _, _, err := ensureProjectBindingExplicit(ctx, handle, consumer.ProjectRoot); err != nil {
			return nil, err
		}
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	reply, err := agentOpenSessionFn(ctx, client, hostLabel, consumer)
	if err != nil {
		return nil, err
	}
	env = append(env, secrettypes.EnvSessionToken+"="+reply.SessionToken)
	if consumer.ProjectRoot != "" {
		env = append(env, secrettypes.EnvAgentProjectRoot+"="+consumer.ProjectRoot)
	}
	return env, nil
}

// registerProtectedProcess registers a process PID with the runtime so it
// receives safe-mode protection. Kept in package app because existing tests
// call it directly.
func registerProtectedProcess(ctx context.Context, s starter, sessionToken string, pid int) error {
	if strings.TrimSpace(sessionToken) == "" || pid <= 0 {
		return nil
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()
	return client.RegisterProcess(ctx, sessionToken, pid)
}

// envValue returns the value of key in a KEY=VALUE env slice, or "".
// Kept in package app because existing tests call it directly.
func envValue(env []string, key string) string {
	prefix := key + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	return ""
}

// supportedAgentConfigPaths returns a map of agentID → config file path for
// all supported agents. Stays in package app because it uses the private
// setupSupportedAgents() function.
func supportedAgentConfigPaths() map[string]string {
	result := map[string]string{}
	for _, spec := range setupSupportedAgents() {
		result[spec.ID] = spec.ConfigPath("")
	}
	return result
}

// genericAgentSupportedProfileView returns the profile view for the
// generic-compatible path as an agentops.AgentSupportedProfileView.
// Stays in package app because it uses private helpers
// (genericCompatibilitySurface, agentGenericPrintConfig, etc.).
func genericAgentSupportedProfileView() agentops.AgentSupportedProfileView {
	generic := genericCompatibilitySurface()
	command, _ := generic["command"].([]string)
	setupCmd, _ := generic["setup_command"].(string)
	doctorCmd, _ := generic["doctor_command"].(string)
	firstProofCmd, _ := generic["first_proof_command"].(string)
	return agentops.AgentSupportedProfileView{
		ID:                 generic["id"].(string),
		Name:               generic["name"].(string),
		SupportTier:        generic["support_tier"].(string),
		CompatibilityLabel: generic["compatibility_label"].(string),
		FirstClass:         generic["first_class"].(bool),
		DocsPath:           genericDocsPath,
		ConfigPath:         "",
		ReleaseGate:        profiles.ReleaseGate{},
		Evals: profiles.SupportCheck{
			Status: "warn",
			Detail: "generic path is intentionally separate from first-class eval proof",
		},
		Benchmarks: profiles.SupportCheck{
			Status: "warn",
			Detail: "generic path is intentionally separate from first-class benchmark proof",
		},
		ConnectCommand:    command,
		SetupCommand:      setupCmd,
		DoctorCommand:     doctorCmd,
		FirstProofCommand: firstProofCmd,
		PrintConfig:       agentGenericPrintConfig(),
		Proof: map[string]profiles.SupportCheck{
			"support_tier": {
				Status: "warn",
				Detail: "generic-compatible broker path is a first-proof path, not first-class support",
			},
			"docs": {
				Status: "pass",
				Detail: "generic broker guide documents setup, first proof, and safe path usage",
			},
		},
	}
}
