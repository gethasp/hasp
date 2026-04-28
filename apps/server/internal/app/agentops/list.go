package agentops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

func agentListHandler(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := newFlagSet(deps, "agent list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	consumers := deps.StoreListAgents(handle)
	payload := map[string]any{"consumers": consumers}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return deps.RenderConsumerList(w, consumers)
	})
}

func agentListSupportedHandler(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := newFlagSet(deps, "agent list-supported", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp agent list-supported [--json]")
	}
	statuses, err := deps.AgentLoadSupportStatuses()
	if err != nil {
		return err
	}
	configPaths := deps.AgentConfigPaths()
	out := make([]AgentSupportedProfileView, 0, len(statuses))
	for _, status := range statuses {
		cp := ""
		if configPaths != nil {
			cp = configPaths[status.Profile.ID]
		}
		out = append(out, AgentSupportedProfileView{
			ID:                 status.Profile.ID,
			Name:               status.Profile.Name,
			SupportTier:        status.SupportTier,
			CompatibilityLabel: status.CompatibilityLabel,
			FirstClass:         status.FirstClass,
			DocsPath:           status.Profile.DocsPath,
			ConfigPath:         cp,
			ReleaseGate:        status.ReleaseGate,
			Evals:              status.Proof["evals"],
			Benchmarks:         status.Proof["benchmarks"],
			ConnectCommand:     status.Profile.Command,
			Proof:              status.Proof,
		})
	}
	if deps.GenericAgentView != nil {
		out = append(out, deps.GenericAgentView())
	}
	payload := map[string]any{"profiles": out}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "profile\ttier\tcompatibility\tdocs\tconnect")
		for _, profile := range out {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", profile.ID, profile.SupportTier, profile.CompatibilityLabel, profile.DocsPath, strings.Join(profile.ConnectCommand, " "))
		}
		return tw.Flush()
	})
}
