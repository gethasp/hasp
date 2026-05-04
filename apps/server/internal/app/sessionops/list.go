package sessionops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func sessionList(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("session list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	mineOnly := fs.Bool("mine", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp session list [--mine] [--json]")
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

	reply, err := client.Status(ctx)
	if err != nil {
		return err
	}
	sessions := reply.Sessions

	if *mineOnly {
		var ld LocalDeps
		if deps.DefaultLocalDeps != nil {
			ld = deps.DefaultLocalDeps()
		} else {
			ld = defaultLocalDepsFallback()
		}
		me, err := ld.LocalUser()
		if err != nil {
			return err
		}
		filtered := sessions[:0:0]
		for _, sv := range sessions {
			if sv.LocalUser == me {
				filtered = append(filtered, sv)
			}
		}
		sessions = filtered
	}

	payload := map[string]any{"sessions": sessions}

	var opts ui.ColorOptions
	if deps.GlobalColorOptions != nil {
		co := deps.GlobalColorOptions(ctx, stdout)
		opts = ui.ColorOptions{
			Interactive: co.Interactive,
			Disable:     co.Disable,
			Quiet:       co.Quiet,
			Verbose:     co.Verbose,
		}
	} else {
		opts = ui.ColorOptions{Interactive: ui.IsInteractiveWriter(stdout)}
	}

	if deps.RenderJSONOrHuman == nil {
		return fmt.Errorf("sessionops: RenderJSONOrHuman not wired")
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSessionListWithColor(w, sessions, opts)
	})
}

// renderSessionListWithColor writes sessions as a colourised tabular listing.
// It is exposed so that package app can delegate directly from the shim,
// and so that existing tests that call renderSessionListWithColor by name
// can continue to compile.
func renderSessionListWithColor(w io.Writer, sessions []runtime.SessionView, opts ui.ColorOptions) error {
	if len(sessions) == 0 {
		_, err := fmt.Fprintln(w, "No active sessions.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	header := "STATE\tID\tHOST\tPROJECT\tCONSUMER\tAGENT_SAFE\tLAST_SEEN\tEXPIRES"
	if opts.Verbose {
		header = "STATE\tID\tUSER\tHOST\tPROJECT\tCONSUMER\tAGENT_SAFE\tLAST_SEEN\tEXPIRES"
	}
	fmt.Fprintln(tw, header)
	now := time.Now()
	for _, sv := range sessions {
		consumer := sv.ConsumerName
		if consumer == "" {
			consumer = "-"
		}
		badge := sessionStateBadge(sv, now, opts)
		if opts.Verbose {
			user := sv.LocalUser
			if user == "" {
				user = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%t\t%s\t%s\n",
				badge, sv.ID, user, sv.HostLabel, sv.ProjectRoot, consumer, sv.AgentSafe,
				sv.LastSeenAt.Format(secrettypes.TimeRFC3339), sv.ExpiresAt.Format(secrettypes.TimeRFC3339),
			)
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%t\t%s\t%s\n",
				badge, sv.ID, sv.HostLabel, sv.ProjectRoot, consumer, sv.AgentSafe,
				sv.LastSeenAt.Format(secrettypes.TimeRFC3339), sv.ExpiresAt.Format(secrettypes.TimeRFC3339),
			)
		}
	}
	return tw.Flush()
}
