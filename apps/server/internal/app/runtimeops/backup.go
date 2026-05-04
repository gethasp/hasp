package runtimeops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func exportBackup(ctx context.Context, deps Deps, args []string, _ io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("export-backup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	outputPath := fs.String("output", "", "")
	// Unsafe argv form: defined so flag.Parse doesn't reject it as unknown,
	// but checked post-parse to emit a helpful rejection message.
	argvPassphrase := fs.String("recovery-passphrase", "", "")
	// Safe forms.
	stdinFlag := fs.Bool("recovery-passphrase-stdin", false, "")
	fdFlag := fs.Int("recovery-passphrase-fd", -1, "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Reject the unsafe argv form before doing anything else.
	if *argvPassphrase != "" {
		if deps.ErrArgvPassphrase != nil {
			return deps.ErrArgvPassphrase
		}
		return errors.New("passphrase via argv is not allowed; use --recovery-passphrase-stdin, --recovery-passphrase-fd N, or HASP_BACKUP_PASSPHRASE")
	}
	if *outputPath == "" {
		return errors.New("usage: hasp export-backup --output <path> (--recovery-passphrase-stdin | --recovery-passphrase-fd N | HASP_BACKUP_PASSPHRASE)")
	}

	var passphrase string
	if deps.ReadPassphrase != nil {
		var err error
		passphrase, err = deps.ReadPassphrase(*stdinFlag, *fdFlag, os.Getenv("HASP_BACKUP_PASSPHRASE"), "HASP_BACKUP_PASSPHRASE")
		if err != nil {
			return err
		}
	} else {
		passphrase = os.Getenv("HASP_BACKUP_PASSPHRASE")
	}

	if deps.ExpandUserPath != nil {
		expanded, err := deps.ExpandUserPath(strings.TrimSpace(*outputPath))
		if err != nil {
			return fmt.Errorf("--output: %w", err)
		}
		*outputPath = expanded
	}

	if deps.OpenVault == nil {
		return errors.New("runtimeops: OpenVault not configured")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}

	checkpoint, err := handle.ExportBackup(ctx, *outputPath, passphrase)
	if err != nil {
		return err
	}

	payload := map[string]any{"output_path": *outputPath, "checkpoint": checkpoint}
	jsonOut := *jsonOutput || globalJSON(ctx, deps)

	if deps.RenderJSONOrHuman != nil {
		return deps.RenderJSONOrHuman(ctx, stdout, jsonOut, payload, func(w io.Writer) error {
			return renderBackupResultFn(deps, w, "Backup exported", "Wrote an encrypted HASP backup.", *outputPath, checkpoint)
		})
	}
	if jsonOut {
		if deps.WriteJSONResponse != nil {
			return deps.WriteJSONResponse(stdout, payload)
		}
	}
	return renderBackupResultFn(deps, stdout, "Backup exported", "Wrote an encrypted HASP backup.", *outputPath, checkpoint)
}

func restoreBackup(ctx context.Context, deps Deps, args []string, _ io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("restore-backup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	inputPath := fs.String("input", "", "")
	// Unsafe argv forms.
	argvPassphrase := fs.String("recovery-passphrase", "", "")
	argvMasterPassword := fs.String("master-password", "", "")
	// Safe forms.
	stdinFlag := fs.Bool("recovery-passphrase-stdin", false, "")
	fdFlag := fs.Int("recovery-passphrase-fd", -1, "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Reject the unsafe argv forms before doing anything else.
	if *argvPassphrase != "" {
		if deps.ErrArgvPassphrase != nil {
			return deps.ErrArgvPassphrase
		}
		return errors.New("passphrase via argv is not allowed; use --recovery-passphrase-stdin, --recovery-passphrase-fd N, or HASP_BACKUP_PASSPHRASE")
	}
	if *argvMasterPassword != "" {
		if deps.ErrArgvMasterPassword != nil {
			return deps.ErrArgvMasterPassword
		}
		return errors.New("master-password via argv is not allowed; use --recovery-passphrase-stdin, --recovery-passphrase-fd N, or HASP_MASTER_PASSWORD")
	}
	if *inputPath == "" {
		return errors.New("usage: hasp restore-backup --input <path> (--recovery-passphrase-stdin | --recovery-passphrase-fd N | HASP_BACKUP_PASSPHRASE)")
	}

	var passphrase string
	if deps.ReadPassphrase != nil {
		var err error
		passphrase, err = deps.ReadPassphrase(*stdinFlag, *fdFlag, os.Getenv("HASP_BACKUP_PASSPHRASE"), "HASP_BACKUP_PASSPHRASE")
		if err != nil {
			return err
		}
	} else {
		passphrase = os.Getenv("HASP_BACKUP_PASSPHRASE")
	}

	var masterPassword string
	if deps.LoadMasterPassword != nil {
		var err error
		masterPassword, err = deps.LoadMasterPassword()
		if err != nil {
			return err
		}
	} else {
		masterPassword = strings.TrimSpace(os.Getenv("HASP_MASTER_PASSWORD"))
		if masterPassword == "" {
			return errors.New("HASP_MASTER_PASSWORD must be set for restore-backup")
		}
	}

	if deps.ExpandUserPath != nil {
		expanded, err := deps.ExpandUserPath(strings.TrimSpace(*inputPath))
		if err != nil {
			return fmt.Errorf("--input: %w", err)
		}
		*inputPath = expanded
	}

	if deps.NewVaultStore == nil {
		return errors.New("runtimeops: NewVaultStore not configured")
	}
	vaultStore, err := deps.NewVaultStore()
	if err != nil {
		return err
	}

	checkpoint, err := vaultStore.RestoreBackup(ctx, *inputPath, passphrase, masterPassword)
	if err != nil {
		return err
	}

	payload := map[string]any{"input_path": *inputPath, "checkpoint": checkpoint}
	jsonOut := *jsonOutput || globalJSON(ctx, deps)

	if deps.RenderJSONOrHuman != nil {
		return deps.RenderJSONOrHuman(ctx, stdout, jsonOut, payload, func(w io.Writer) error {
			return renderBackupResultFn(deps, w, "Backup restored", "Restored the HASP vault from an encrypted backup.", *inputPath, checkpoint)
		})
	}
	if jsonOut {
		if deps.WriteJSONResponse != nil {
			return deps.WriteJSONResponse(stdout, payload)
		}
	}
	return renderBackupResultFn(deps, stdout, "Backup restored", "Restored the HASP vault from an encrypted backup.", *inputPath, checkpoint)
}
