package runtimeops

import (
	"context"
	"flag"
	"io"
)

func pingHandler(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
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

	reply, err := client.Ping(ctx)
	if err != nil {
		return err
	}

	if deps.RenderPingJSONOrHuman != nil {
		return deps.RenderPingJSONOrHuman(ctx, stdout, jsonOut, reply)
	}
	// Minimal fallback (no panic for contract test).
	if jsonOut {
		if deps.WriteJSONResponse != nil {
			return deps.WriteJSONResponse(stdout, reply)
		}
	}
	if deps.RenderJSONOrHuman != nil {
		return deps.RenderJSONOrHuman(ctx, stdout, jsonOut, reply, func(w io.Writer) error {
			_, e := io.WriteString(w, reply.Name+"\n")
			return e
		})
	}
	_, err = io.WriteString(stdout, reply.Name+"\n")
	return err
}
