package runtimeops

import (
	"context"
	"flag"
	"io"
)

func statusHandler(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var s Starter
	if deps.NewStarter != nil {
		var err error
		s, err = deps.NewStarter()
		if err != nil {
			return err
		}
	}

	jsonOut := *jsonOutput || globalJSON(ctx, deps)
	client := connectIfRunningFn(ctx, deps, s)
	if client == nil {
		return renderNotRunningFn(deps, stdout, jsonOut)
	}
	defer client.Close()

	reply, err := client.Status(ctx)
	if err != nil {
		return err
	}

	if jsonOut {
		if deps.WriteJSONResponse != nil {
			return deps.WriteJSONResponse(stdout, reply)
		}
		if deps.RenderJSONOrHuman != nil {
			return deps.RenderJSONOrHuman(ctx, stdout, true, reply, func(w io.Writer) error {
				return renderStatusHumanFallback(w, reply, deps.TerminalColumns)
			})
		}
	}

	if deps.RenderStatusHuman != nil {
		return deps.RenderStatusHuman(stdout, reply, deps.TerminalColumns)
	}
	return renderStatusHumanFallback(stdout, reply, deps.TerminalColumns)
}
