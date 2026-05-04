package app

import (
	"context"
	"io"
	"os/exec"

	"github.com/gethasp/hasp/apps/server/internal/app/agentops"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// defaultAgentDeps builds an agentops.Deps wired to the package-level seam
// vars. Each closure reads the current value of its seam var at call time, so
// test overrides of storeGetAgentFn, agentBuildExecutionEnvFn, etc. propagate
// transparently through the agentops handlers.
func defaultAgentDeps() agentops.Deps {
	return agentops.Deps{
		// ── The 14 named seams pinned by the contract test ────────────────────

		StoreGetAgent: func(handle *store.Handle, name string) (store.AgentConsumer, error) {
			return storeGetAgentFn(handle, name)
		},
		StoreListAgents: func(handle *store.Handle) []store.AgentConsumer {
			return storeListAgentsFn(handle)
		},
		StoreUpsertAgent: func(handle *store.Handle, consumer store.AgentConsumer) (store.AgentConsumer, error) {
			return storeUpsertAgentFn(handle, consumer)
		},
		StoreDeleteAgent: func(handle *store.Handle, name string) error {
			return storeDeleteAgentFn(handle, name)
		},
		RemoveAgentConsumerConfig: func(agentID string, configPath string) error {
			specs := setupSupportedAgents()
			selected, err := selectSetupAgents(specs, []string{agentID})
			if err != nil {
				return err
			}
			return removeAgentConsumerConfigFn(selected[0], configPath)
		},
		AgentAtomicWrite: func(path string, existing []byte, updated []byte) (string, bool, error) {
			return agentAtomicWriteFn(path, existing, updated)
		},
		AgentUserShell: func() string {
			return agentUserShellFn()
		},
		AgentExecCommandContext: func(ctx context.Context, name string, arg ...string) *exec.Cmd {
			return agentExecCommandContextFn(ctx, name, arg...)
		},
		AgentNewStarter: func() (agentops.Starter, error) {
			// *runtimeStarter satisfies agentops.Starter via structural typing.
			return agentNewStarterFn()
		},
		AgentBuildExecutionEnv: func(ctx context.Context, handle *store.Handle, consumer store.AgentConsumer, s agentops.Starter, hostLabel string) ([]string, error) {
			// s was created by AgentNewStarter which calls agentNewStarterFn()
			// returning *runtimeStarter — it implements both agentops.Starter and
			// the package-private starter interface.
			return agentBuildExecutionEnvFn(ctx, handle, consumer, s.(starter), hostLabel)
		},
		AgentRegisterProcess: func(ctx context.Context, s agentops.Starter, sessionToken string, pid int) error {
			return agentRegisterProcessFn(ctx, s.(starter), sessionToken, pid)
		},
		AgentServeMCP: func(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
			return agentServeMCPFn(ctx, stdin, stdout)
		},
		AgentLoadSupportStatuses: agentLoadSupportStatusesFn,
		AgentOpenSession: func(ctx context.Context, client *runtime.Client, hostLabel string, consumer store.AgentConsumer) (runtime.OpenSessionResponse, error) {
			return agentOpenSessionFn(ctx, client, hostLabel, consumer)
		},

		// ── Additional deps ───────────────────────────────────────────────────

		OpenVault: func(ctx context.Context) (*store.Handle, error) {
			return openVaultHandleFn(ctx)
		},
		SetEnv: func(key string, value string) (func(), error) {
			return setupSetEnvFn(key, value)
		},
		ExpandUserPath: expandUserPath,
		ResolvePaths: func() (string, error) {
			resolved, err := appResolvePathsFn()
			if err != nil {
				return "", err
			}
			return resolved.HomeDir, nil
		},
		ResolveProjectRoot: secretProjectContext,
		EnsureProjectBinding: func(ctx context.Context, handle *store.Handle, root string) error {
			_, _, _, err := ensureProjectBindingExplicit(ctx, handle, root)
			return err
		},
		WriteAgentConfig: func(agentID string, homeDir string) (agentops.AgentSetupOutcome, error) {
			supported := setupSupportedAgents()
			selected, err := selectSetupAgents(supported, []string{agentID})
			if err != nil {
				return agentops.AgentSetupOutcome{}, err
			}
			outcomes, err := setupWriteAgentConfigsFn(selected, homeDir)
			if err != nil {
				return agentops.AgentSetupOutcome{}, err
			}
			o := outcomes[0]
			return agentops.AgentSetupOutcome{
				ID:         o.ID,
				Label:      o.Label,
				ConfigPath: o.ConfigPath,
				BackupPath: o.BackupPath,
				Changed:    o.Changed,
			}, nil
		},
		AgentConfigPaths: supportedAgentConfigPaths,
		GenericAgentView: genericAgentSupportedProfileView,
		AppendAudit:      appendAudit,
		RenderJSONOrHuman: renderJSONOrHuman,
		RenderConnectResult: func(out io.Writer, consumer store.AgentConsumer, outcome agentops.AgentSetupOutcome) error {
			return renderAgentConsumerSummary(out, "Agent connected", "Saved the agent configuration.", consumer, setupAgentOutcome{
				ID:         outcome.ID,
				Label:      outcome.Label,
				ConfigPath: outcome.ConfigPath,
				BackupPath: outcome.BackupPath,
				Changed:    outcome.Changed,
			})
		},
		RenderConsumerList: renderAgentConsumerList,
		RenderSimpleAction: renderSimpleAction,
		IsHelpArg:          isHelpArg,
		PrintHelpTopic:     printHelpTopic,
		NewFlagSet:         nil, // use agentops default (flag.NewFlagSet)
	}
}
