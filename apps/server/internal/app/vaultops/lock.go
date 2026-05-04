package vaultops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
)

func lock(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("vault lock", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp vault lock [--json]")
	}

	grantDeps := resolveGrantOpsDeps(deps)

	revokedSessions := 0
	if deps.NewStarter != nil {
		s, err := deps.NewStarter()
		if err == nil && s != nil {
			client, connErr := s.Connect(ctx)
			if connErr == nil && client != nil {
				reply, lockErr := client.LockVault(ctx)
				_ = client.Close()
				if lockErr != nil {
					return lockErr
				}
				revokedSessions = reply.RevokedCount
			}
		}
	}

	revokedGrants := 0
	convenienceState := "unchanged"
	if deps.OpenVaultHandle != nil {
		if handle, openErr := deps.OpenVaultHandle(ctx); openErr == nil {
			if count, revokeErr := grantDeps.RevokeAllGrants(handle); revokeErr != nil {
				return revokeErr
			} else {
				revokedGrants = count
			}
			hadWrap, forgetErr := grantDeps.DisableConvenienceUnlock(handle, ctx)
			if forgetErr != nil {
				return forgetErr
			}
			if hadWrap {
				convenienceState = "forgotten"
			}
		}
	}

	payload := map[string]any{
		"vault_state":       "locked",
		"revoked_sessions":  revokedSessions,
		"revoked_grants":    revokedGrants,
		"convenience_state": convenienceState,
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return deps.RenderSimpleAction(ctx, w, "Vault locked", "Revoked active sessions, grants, and the saved keychain unlock.",
			cliPair("Vault state", "locked"),
			cliPair("Revoked sessions", fmt.Sprintf("%d", revokedSessions)),
			cliPair("Revoked grants", fmt.Sprintf("%d", revokedGrants)),
			cliPair("Convenience unlock", convenienceState),
		)
	})
}

func forgetDevice(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("vault forget-device", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp vault forget-device [--json]")
	}

	grantDeps := resolveGrantOpsDeps(deps)

	handle, err := deps.OpenVaultHandle(ctx)
	if err != nil {
		return err
	}
	hadWrap, err := grantDeps.DisableConvenienceUnlock(handle, ctx)
	if err != nil {
		return err
	}
	state := "already_forgotten"
	if hadWrap {
		state = "forgotten"
	}
	payload := map[string]any{
		"had_wrap":          hadWrap,
		"convenience_state": state,
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		summary := "The convenience-unlock keychain entry is already cleared."
		if hadWrap {
			summary = "Deleted the keychain entry and cleared the saved convenience-unlock wrap."
		}
		return deps.RenderSimpleAction(ctx, w, "Device forgotten", summary,
			cliPair("Convenience unlock", state),
			cliPair("Had saved wrap", fmt.Sprintf("%t", hadWrap)),
		)
	})
}
