package vaultops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
)

func rekey(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("vault rekey", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp vault rekey [--json]")
	}
	oldPassword, err := deps.LoadMasterPassword()
	if err != nil {
		return fmt.Errorf("vault rekey requires HASP_MASTER_PASSWORD: %w", err)
	}
	newPassword, err := deps.LoadNewMasterPassword()
	if err != nil {
		return err
	}
	handle, err := deps.OpenVaultHandle(ctx)
	if err != nil {
		return err
	}
	if err := handle.RekeyPassword(ctx, oldPassword, newPassword); err != nil {
		return err
	}
	payload := map[string]any{
		"vault_state":         "rekey_complete",
		"convenience_cleared": true,
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return deps.RenderSimpleAction(ctx, w, "Vault password rotated",
			"Rewrapped the vault key under the new master password and cleared the saved keychain unlock.",
			cliPair("Vault state", "rekey_complete"),
			cliPair("Convenience unlock", "cleared"),
		)
	})
}

func rekdf(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("vault rekdf", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp vault rekdf [--json]")
	}
	password, err := deps.LoadMasterPassword()
	if err != nil {
		return fmt.Errorf("vault rekdf requires HASP_MASTER_PASSWORD: %w", err)
	}
	handle, err := deps.OpenVaultHandle(ctx)
	if err != nil {
		return err
	}
	from, to, err := handle.RekdfWithPassword(ctx, password)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"vault_state": "rekdf_complete",
		"from_kdf":    from,
		"to_kdf":      to,
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return deps.RenderSimpleAction(ctx, w, "Vault KDF rewritten",
			fmt.Sprintf("Re-derived the password wrap from %s to %s without rotating the underlying vault key.", from, to),
			cliPair("From KDF", from),
			cliPair("To KDF", to),
		)
	})
}
