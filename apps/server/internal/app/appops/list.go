package appops

import (
	"context"
	"errors"
	"flag"
	"io"
)

func appListHandler(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := newFlagSet(deps, "app list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if deps.OpenVault == nil {
		return errors.New("appops: OpenVault dep not wired")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	consumers := deps.StoreListApps(handle)
	payload := map[string]any{"consumers": consumers}
	if deps.RenderJSONOrHuman == nil {
		return nil
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		if deps.RenderConsumerList != nil {
			return deps.RenderConsumerList(w, consumers)
		}
		return nil
	})
}
