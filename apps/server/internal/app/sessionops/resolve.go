package sessionops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
)

func sessionResolve(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("session resolve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	token := fs.String("token", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" {
		return errors.New("usage: hasp session resolve --token <token>")
	}

	if deps.NewStarter == nil {
		return fmt.Errorf("sessionops: NewStarter not wired")
	}
	s, err := deps.NewStarter()
	if err != nil {
		return err
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()

	reply, err := client.ResolveSession(ctx, *token)
	if err != nil {
		return err
	}

	if deps.RenderJSONOrHuman == nil {
		return fmt.Errorf("sessionops: RenderJSONOrHuman not wired")
	}
	if deps.RenderSessionResolveResult == nil {
		return fmt.Errorf("sessionops: RenderSessionResolveResult not wired")
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, reply, func(w io.Writer) error {
		return deps.RenderSessionResolveResult(w, reply)
	})
}
