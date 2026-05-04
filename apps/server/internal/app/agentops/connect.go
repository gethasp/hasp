package agentops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func agentConnectHandler(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	name, remaining := consumerNameAndArgs(args)
	fs := newFlagSet(deps, "agent connect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", "", "")
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		return errors.New("usage: hasp agent connect <agent-id> [--project-root <path>]")
	}
	if deps.ExpandUserPath != nil {
		if expandedRoot, expandErr := deps.ExpandUserPath(strings.TrimSpace(*projectRoot)); expandErr != nil {
			return fmt.Errorf("--project-root: %w", expandErr)
		} else {
			*projectRoot = expandedRoot
		}
	}
	agentID := strings.TrimSpace(name)
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	consumerProjectRoot := ""
	if strings.TrimSpace(*projectRoot) != "" {
		root, _, err := deps.ResolveProjectRoot(ctx, *projectRoot)
		if err != nil {
			return err
		}
		if err := deps.EnsureProjectBinding(ctx, handle, root); err != nil {
			return err
		}
		consumerProjectRoot = root
	}
	homeDir, err := deps.ResolvePaths()
	if err != nil {
		return err
	}
	outcome, err := deps.WriteAgentConfig(agentID, homeDir)
	if err != nil {
		return err
	}
	consumer, err := deps.StoreUpsertAgent(handle, store.AgentConsumer{
		Name:        agentID,
		AgentID:     agentID,
		ProjectRoot: consumerProjectRoot,
		ConfigPath:  outcome.ConfigPath,
	})
	if err != nil {
		return err
	}
	if deps.AppendAudit != nil {
		deps.AppendAudit(audit.EventRun, "user", map[string]any{
			"action":        "consumer.agent.connect",
			"consumer_type": "agent",
			"consumer_name": consumer.Name,
			"project_root":  consumer.ProjectRoot,
			"config_path":   consumer.ConfigPath,
			"outcome":       "connected",
		})
	}
	payload := map[string]any{"consumer": consumer, "config": outcome}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return deps.RenderConnectResult(w, consumer, outcome)
	})
}

func agentDisconnectHandler(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	name, remaining := consumerNameAndArgs(args)
	fs := newFlagSet(deps, "agent disconnect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		return errors.New("usage: hasp agent disconnect <agent-id>")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	consumer, err := deps.StoreGetAgent(handle, name)
	if err != nil {
		return err
	}
	if err := deps.RemoveAgentConsumerConfig(consumer.AgentID, consumer.ConfigPath); err != nil {
		return err
	}
	if err := deps.StoreDeleteAgent(handle, consumer.Name); err != nil {
		return err
	}
	if deps.AppendAudit != nil {
		deps.AppendAudit(audit.EventRun, "user", map[string]any{
			"action":        "consumer.agent.disconnect",
			"consumer_type": "agent",
			"consumer_name": consumer.Name,
			"config_path":   consumer.ConfigPath,
			"outcome":       "disconnected",
		})
	}
	payload := map[string]any{"consumer_name": consumer.Name, "outcome": "disconnected"}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return deps.RenderSimpleAction(ctx, w, "Agent disconnected", "Removed the saved agent.",
			cliPair("Name", consumer.Name),
			cliPair("Outcome", "disconnected"),
		)
	})
}
