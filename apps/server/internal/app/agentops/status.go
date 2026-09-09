package agentops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
)

func agentStatusHandler(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	name, remaining := consumerNameAndArgs(args)
	fs := newFlagSet(deps, "agent status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if name == "" || fs.NArg() != 0 {
		return errors.New("usage: hasp agent status <agent-id> [--json]")
	}
	if deps.AgentStatus == nil {
		return errors.New("agent status diagnostics are unavailable")
	}
	status, err := deps.AgentStatus(ctx, name)
	if err != nil {
		return err
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, status, func(w io.Writer) error {
		pairs := [][2]string{}
		for _, key := range []string{"agent_id", "client_installed", "configuration", "config_path", "wrapper", "connection", "process_protection", "process_scope", "session_consumer", "project_plaintext_policy", "repair", "protected_launch"} {
			if value, ok := status[key]; ok {
				pairs = append(pairs, [2]string{key, fmt.Sprint(value)})
			}
		}
		return deps.RenderSimpleAction(ctx, w, "Agent status", "Installation and the current command's protection are checked separately. Run this command through the client's shell tool to inspect that process tree.", pairs...)
	})
}
