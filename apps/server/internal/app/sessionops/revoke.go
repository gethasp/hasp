package sessionops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
)

func sessionRevoke(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("session revoke", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	token := fs.String("token", "", "")
	all := fs.Bool("all", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *all && *token != "" {
		return errors.New("choose either --all or --token")
	}
	if !*all && *token == "" {
		return errors.New("usage: hasp session revoke (--token <token> | --all)")
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

	if deps.RenderJSONOrHuman == nil {
		return fmt.Errorf("sessionops: RenderJSONOrHuman not wired")
	}
	if deps.RenderSimpleAction == nil {
		return fmt.Errorf("sessionops: RenderSimpleAction not wired")
	}

	if *all {
		reply, err := client.RevokeAllSessions(ctx)
		if err != nil {
			return err
		}
		revokedGrants := 0
		if deps.OpenVault != nil {
			if handle, openErr := deps.OpenVault(ctx); openErr == nil {
				grantOps := resolveGrantOps(deps)
				if count, revokeErr := grantOps.RevokeAllGrants(handle); revokeErr != nil {
					return revokeErr
				} else {
					revokedGrants = count
				}
			}
		}
		payload := map[string]any{"outcome": "revoked_all", "revoked_sessions": reply.RevokedCount, "revoked_grants": revokedGrants}
		return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
			return deps.RenderSimpleAction(ctx, w, "Sessions revoked", "Revoked all daemon-backed sessions.",
				cliPair("Outcome", "revoked_all"),
				cliPair("Revoked sessions", fmt.Sprintf("%d", reply.RevokedCount)),
				cliPair("Revoked grants", fmt.Sprintf("%d", revokedGrants)),
			)
		})
	}

	if err := client.RevokeSession(ctx, *token); err != nil {
		return err
	}
	payload := map[string]any{"token": *token, "outcome": "revoked"}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return deps.RenderSimpleAction(ctx, w, "Session revoked", "Revoked the daemon-backed session.",
			cliPair("Token", *token),
			cliPair("Outcome", "revoked"),
		)
	})
}
