package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/mcp"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/profiles"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

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

func agentConsumerCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		return printHelpTopic(stdout, []string{"agent"})
	}
	if len(args) > 1 && isHelpArg(args[1]) {
		return printHelpTopic(stdout, []string{"agent", args[0]})
	}
	switch args[0] {
	case "connect":
		return agentConnectCommand(ctx, args[1:], stdout)
	case "mcp":
		return agentMCPCommand(ctx, args[1:], stdin, stdout)
	case "launch":
		return agentLaunchCommand(ctx, args[1:], stdin, stdout, stderr, false)
	case "shell":
		return agentLaunchCommand(ctx, args[1:], stdin, stdout, stderr, true)
	case "disconnect":
		return agentDisconnectCommand(ctx, args[1:], stdout)
	case "list":
		return agentListCommand(ctx, args[1:], stdout)
	case "list-supported":
		return agentListSupportedCommand(args[1:], stdout)
	default:
		return fmt.Errorf("unknown agent subcommand %q", args[0])
	}
}

type agentSupportedProfileView struct {
	ID                 string                           `json:"id"`
	Name               string                           `json:"name"`
	SupportTier        string                           `json:"support_tier"`
	CompatibilityLabel string                           `json:"compatibility_label"`
	FirstClass         bool                             `json:"first_class"`
	DocsPath           string                           `json:"docs_path"`
	ConfigPath         string                           `json:"config_path"`
	ReleaseGate        profiles.ReleaseGate             `json:"release_gate"`
	Evals              profiles.SupportCheck            `json:"evals"`
	Benchmarks         profiles.SupportCheck            `json:"benchmarks"`
	ConnectCommand     []string                         `json:"connect_command"`
	Proof              map[string]profiles.SupportCheck `json:"proof"`
	SetupCommand       string                           `json:"setup_command"`
	DoctorCommand      string                           `json:"doctor_command"`
	FirstProofCommand  string                           `json:"first_proof_command"`
	PrintConfig        map[string]string                `json:"print_config"`
}

func agentListSupportedCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("agent list-supported", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp agent list-supported [--json]")
	}
	statuses, err := agentLoadSupportStatusesFn()
	if err != nil {
		return err
	}
	configPaths := supportedAgentConfigPaths()
	out := make([]agentSupportedProfileView, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, agentSupportedProfileView{
			ID:                 status.Profile.ID,
			Name:               status.Profile.Name,
			SupportTier:        status.SupportTier,
			CompatibilityLabel: status.CompatibilityLabel,
			FirstClass:         status.FirstClass,
			DocsPath:           status.Profile.DocsPath,
			ConfigPath:         configPaths[status.Profile.ID],
			ReleaseGate:        status.ReleaseGate,
			Evals:              status.Proof["evals"],
			Benchmarks:         status.Proof["benchmarks"],
			ConnectCommand:     status.Profile.Command,
			Proof:              status.Proof,
		})
	}
	out = append(out, genericAgentSupportedProfileView())
	payload := map[string]any{"profiles": out}
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "profile\ttier\tcompatibility\tdocs\tconnect")
		for _, profile := range out {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", profile.ID, profile.SupportTier, profile.CompatibilityLabel, profile.DocsPath, strings.Join(profile.ConnectCommand, " "))
		}
		return tw.Flush()
	})
}

func genericAgentSupportedProfileView() agentSupportedProfileView {
	generic := genericCompatibilitySurface()
	command, _ := generic["command"].([]string)
	setupCmd, _ := generic["setup_command"].(string)
	doctorCmd, _ := generic["doctor_command"].(string)
	firstProofCmd, _ := generic["first_proof_command"].(string)
	return agentSupportedProfileView{
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

func supportedAgentConfigPaths() map[string]string {
	paths := map[string]string{}
	for _, spec := range setupSupportedAgents() {
		paths[spec.ID] = spec.ConfigPath("")
	}
	return paths
}

func agentConnectCommand(ctx context.Context, args []string, stdout io.Writer) error {
	name, remaining := consumerNameAndArgs(args)
	fs := flag.NewFlagSet("agent connect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", "", "")
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		return errors.New("usage: hasp agent connect <agent-id> [--project-root <path>]")
	}
	agentID := strings.TrimSpace(name)
	supported := setupSupportedAgents()
	selected, err := selectSetupAgents(supported, []string{agentID})
	if err != nil {
		return err
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	consumerProjectRoot := ""
	if strings.TrimSpace(*projectRoot) != "" {
		root, _, err := secretProjectContext(ctx, *projectRoot)
		if err != nil {
			return err
		}
		if _, _, _, err := ensureProjectBindingExplicit(ctx, handle, root); err != nil {
			return err
		}
		consumerProjectRoot = root
	}
	resolved, err := appResolvePathsFn()
	if err != nil {
		return err
	}
	outcomes, err := setupWriteAgentConfigsFn(selected, resolved.HomeDir)
	if err != nil {
		return err
	}
	outcome := outcomes[0]
	consumer, err := storeUpsertAgentFn(handle, store.AgentConsumer{
		Name:        agentID,
		AgentID:     agentID,
		ProjectRoot: consumerProjectRoot,
		ConfigPath:  outcome.ConfigPath,
	})
	if err != nil {
		return err
	}
	appendAudit(audit.EventRun, "user", map[string]any{
		"action":        "consumer.agent.connect",
		"consumer_type": "agent",
		"consumer_name": consumer.Name,
		"project_root":  consumer.ProjectRoot,
		"config_path":   consumer.ConfigPath,
		"outcome":       "connected",
	})
	payload := map[string]any{"consumer": consumer, "config": outcome}
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderAgentConsumerSummary(w, "Agent connected", "Saved the agent consumer configuration.", consumer, outcome)
	})
}

func agentDisconnectCommand(ctx context.Context, args []string, stdout io.Writer) error {
	name, remaining := consumerNameAndArgs(args)
	fs := flag.NewFlagSet("agent disconnect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		return errors.New("usage: hasp agent disconnect <agent-id>")
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	consumer, err := storeGetAgentFn(handle, name)
	if err != nil {
		return err
	}
	specs := setupSupportedAgents()
	selected, err := selectSetupAgents(specs, []string{consumer.AgentID})
	if err != nil {
		return err
	}
	if err := removeAgentConsumerConfigFn(selected[0], consumer.ConfigPath); err != nil {
		return err
	}
	if err := storeDeleteAgentFn(handle, consumer.Name); err != nil {
		return err
	}
	appendAudit(audit.EventRun, "user", map[string]any{
		"action":        "consumer.agent.disconnect",
		"consumer_type": "agent",
		"consumer_name": consumer.Name,
		"config_path":   consumer.ConfigPath,
		"outcome":       "disconnected",
	})
	payload := map[string]any{"consumer_name": consumer.Name, "outcome": "disconnected"}
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSimpleAction(w, "Agent disconnected", "Removed the saved agent consumer.",
			cliPair("Name", consumer.Name),
			cliPair("Outcome", "disconnected"),
		)
	})
}

func agentListCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("agent list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	consumers := storeListAgentsFn(handle)
	payload := map[string]any{"consumers": consumers}
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderAgentConsumerList(w, consumers)
	})
}

func agentLaunchCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, shellMode bool) error {
	name, remaining := consumerNameAndArgs(args)
	commandName := "agent launch"
	usage := "usage: hasp agent launch <agent-id> -- <command...>"
	if shellMode {
		commandName = "agent shell"
		usage = "usage: hasp agent shell <agent-id> [shell args...]"
	}
	fs := flag.NewFlagSet(commandName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" {
		return errors.New(usage)
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	consumer, err := storeGetAgentFn(handle, name)
	if errors.Is(err, store.ErrConsumerNotFound) {
		consumer = store.AgentConsumer{
			Name:        name,
			AgentID:     name,
			ProjectRoot: strings.TrimSpace(os.Getenv(envAgentProjectRoot)),
		}
	} else if err != nil {
		return err
	}
	starter, err := agentNewStarterFn()
	if err != nil {
		return err
	}
	command := fs.Args()
	if shellMode {
		shell := strings.TrimSpace(agentUserShellFn())
		if shell == "" {
			shell = "/bin/sh"
		}
		command = append([]string{shell, "-l"}, command...)
	} else if len(command) == 0 {
		return errors.New(usage)
	}
	env, err := agentBuildExecutionEnvFn(ctx, handle, consumer, starter, "agent:"+consumer.Name)
	if err != nil {
		return err
	}
	cmd := agentExecCommandContextFn(ctx, command[0], command[1:]...)
	if consumer.ProjectRoot != "" {
		cmd.Dir = consumer.ProjectRoot
	}
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	if token := envValue(env, envSessionToken); token != "" {
		if err := agentRegisterProcessFn(ctx, starter, token, cmd.Process.Pid); err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return err
		}
	}
	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("command exited with code %d", exitErr.ExitCode())
		}
		return err
	}
	appendAudit(audit.EventRun, "user", map[string]any{
		"action":        "consumer.agent.launch",
		"consumer_type": "agent",
		"consumer_name": consumer.Name,
		"project_root":  consumer.ProjectRoot,
		"command":       command,
		"shell_mode":    shellMode,
		"outcome":       "completed",
	})
	return nil
}

func agentMCPCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	name, remaining := consumerNameAndArgs(args)
	fs := flag.NewFlagSet("agent mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		return errors.New("usage: hasp agent mcp <agent-id>")
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	consumer, err := storeGetAgentFn(handle, name)
	if err != nil {
		return err
	}
	starter, err := agentNewStarterFn()
	if err != nil {
		return err
	}
	env, err := agentBuildExecutionEnvFn(ctx, handle, consumer, starter, "agent:"+consumer.Name)
	if err != nil {
		return err
	}
	if token := envValue(env, envSessionToken); token != "" {
		if err := agentRegisterProcessFn(ctx, starter, token, os.Getppid()); err != nil {
			return err
		}
	}
	restores := make([]func(), 0, len(env))
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		restore, err := setupSetEnvFn(key, value)
		if err != nil {
			return err
		}
		restores = append(restores, restore)
	}
	defer func() {
		for i := len(restores) - 1; i >= 0; i-- {
			restores[i]()
		}
	}()
	return agentServeMCPFn(ctx, stdin, stdout)
}

func buildAgentExecutionEnv(ctx context.Context, handle *store.Handle, consumer store.AgentConsumer, s starter, hostLabel string) ([]string, error) {
	resolved, err := appResolvePathsFn()
	if err != nil {
		return nil, err
	}
	env := []string{
		paths.EnvHome + "=" + resolved.HomeDir,
		envAgentSafeMode + "=1",
		envAgentConsumer + "=" + consumer.Name,
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
	env = append(env, envSessionToken+"="+reply.SessionToken)
	if consumer.ProjectRoot != "" {
		env = append(env, envAgentProjectRoot+"="+consumer.ProjectRoot)
	}
	return env, nil
}

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

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	return ""
}
