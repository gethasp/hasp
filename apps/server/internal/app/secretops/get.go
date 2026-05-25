package secretops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	revealcore "github.com/gethasp/hasp/apps/server/internal/app/reveal"
	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func secretGetCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretGetWithMode(ctx, deps, args, "auto", stdin, stdout, stderr)
}

func secretShowCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretGetWithMode(ctx, deps, args, "show", stdin, stdout, stderr)
}

func secretRevealCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretGetWithMode(ctx, deps, args, "reveal", stdin, stdout, stderr)
}

func secretCopyCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretGetWithMode(ctx, deps, args, "copy", stdin, stdout, stderr)
}

// secretGetWithMode powers `secret show|reveal|copy` (intent-fixed) and
// `secret get|retrieve` (legacy, dispatch via --reveal/--copy flags).
func secretGetWithMode(ctx context.Context, deps Deps, args []string, mode string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := newFlagSet(deps, "secret "+mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	reveal := fs.Bool("reveal", false, "")
	copyValue := fs.Bool("copy", false, "")
	// --newline / --no-newline control trailing newline on raw (non-JSON) reveal
	// output independently of TTY detection.
	newlineFlag := fs.Bool("newline", false, "")
	noNewlineFlag := fs.Bool("no-newline", false, "")
	// Allow flags to appear after positional args (e.g. "NAME --reveal").
	args = reorderFlagsBeforePositionals(fs, args)
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch mode {
	case "show":
		if *reveal {
			return errors.New("secret show does not accept --reveal; use `hasp secret reveal` instead")
		}
		if *copyValue {
			return errors.New("secret show does not accept --copy; use `hasp secret copy` instead")
		}
	case "reveal":
		if *copyValue {
			return errors.New("secret reveal does not accept --copy; use `hasp secret copy` instead")
		}
		*reveal = true
	case "copy":
		if *reveal {
			return errors.New("secret copy does not accept --reveal; use `hasp secret reveal` instead")
		}
		*copyValue = true
	}
	if *reveal && *copyValue {
		return errors.New("choose either --reveal or --copy")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	prompt := deps.NewSecretPrompt(stdin, stdout, stderr)
	names, err := secretNameInputs(fs.Args(), prompt, "Key name")
	if err != nil {
		return err
	}
	if len(names) != 1 {
		return errors.New("secret get expects exactly one secret name")
	}
	item, err := deps.GetItem(handle, names[0])
	if err != nil {
		if errors.Is(err, store.ErrItemNotFound) {
			return deps.NewNotFoundError(
				fmt.Sprintf("secret %q not found in vault", names[0]),
				"run `hasp list` to see managed secret names",
			)
		}
		return err
	}
	metadata := secrettypes.MetadataView{
		Name:           item.Name,
		NamedReference: store.NamedReference(item.Name),
		Kind:           item.Kind,
		CreatedAt:      item.CreatedAt.Format(secrettypes.TimeRFC3339),
		UpdatedAt:      item.UpdatedAt.Format(secrettypes.TimeRFC3339),
		Exposures:      deps.ItemExposures(handle, item.Name),
	}
	switch {
	case *reveal:
		revealed, err := revealcore.Run(ctx, revealcore.Request{Ref: item.Name}, revealcore.Deps{
			Find: func(context.Context, string) (revealcore.Payload, error) {
				return revealcore.FromItem(item), nil
			},
			Authorize: func(ctx context.Context, payload revealcore.Payload) error {
				return deps.EnforceSecretPlaintextPolicyInteractive(ctx, handle, payload.Name, store.PlaintextReveal, stdin, stderr)
			},
			Audit: func(context.Context, revealcore.Payload) error {
				deps.AppendAuditCLI("read", map[string]any{
					"action":      "secret.get.reveal",
					"surface":     "cli",
					"actor_label": deps.ActorLabel(),
					"item_name":   item.Name,
					"outcome":     "revealed",
				})
				return nil
			},
		})
		if err != nil {
			return err
		}
		if *jsonOutput || deps.GlobalFlagsJSON(ctx) {
			return deps.WriteJSONResponse(stdout, deps.SecretGetJSONPayload(metadata, false, true, revealed.Value))
		}
		if _, err := stdout.Write(revealed.Value); err != nil {
			return err
		}
		// Trailing-newline policy (hasp-jx3r):
		//   --newline    → always append
		//   --no-newline → never append
		//   default      → append only when stdout is a TTY
		if item.Kind == store.ItemKindKV {
			appendNL := false
			switch {
			case *noNewlineFlag:
				appendNL = false
			case *newlineFlag:
				appendNL = true
			default:
				appendNL = deps.RevealIsTTY(stdout)
			}
			if appendNL {
				_, err = fmt.Fprintln(stdout)
				return err
			}
		}
		return nil
	case *copyValue:
		if err := deps.EnforceSecretPlaintextPolicyInteractive(ctx, handle, item.Name, store.PlaintextCopy, stdin, stderr); err != nil {
			return err
		}
		if err := deps.ClipboardCopy(item.Value); err != nil {
			return err
		}
		deps.AppendAuditCLI("read", map[string]any{
			"action":      "secret.get.copy",
			"surface":     "cli",
			"actor_label": deps.ActorLabel(),
			"item_name":   item.Name,
			"outcome":     "copied",
		})
		return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, deps.SecretGetJSONPayload(metadata, true, false, nil), func(w io.Writer) error {
			return deps.RenderSecretMetadata(w, metadata, true)
		})
	default:
		return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, deps.SecretGetJSONPayload(metadata, false, false, nil), func(w io.Writer) error {
			return deps.RenderSecretMetadata(w, metadata, false)
		})
	}
}

func secretDeleteCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := newFlagSet(deps, "secret delete", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	assumeYes := fs.Bool("yes", false, "")
	args = reorderFlagsBeforePositionals(fs, args)
	if err := fs.Parse(args); err != nil {
		return err
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	prompt := deps.NewSecretPrompt(stdin, stdout, stderr)
	names, err := secretNameInputs(fs.Args(), prompt, "Key name")
	if err != nil {
		return err
	}
	deleted := make([]secrettypes.MutationView, 0, len(names))
	missing := make([]string, 0)
	for _, name := range names {
		exposures := deps.ItemExposures(handle, name)
		if !*assumeYes && !deps.GlobalFlagsYes(ctx) {
			ok, err := prompt.Confirm(fmt.Sprintf("Delete %s", name), false)
			if err != nil {
				return err
			}
			if !ok {
				missing = append(missing, name)
				continue
			}
		}
		if err := deps.DeleteItem(handle, name); err != nil {
			if errors.Is(err, store.ErrItemNotFound) {
				missing = append(missing, name)
				continue
			}
			return err
		}
		deleted = append(deleted, secrettypes.MutationView{Name: name, NamedReference: store.NamedReference(name), Outcome: "deleted", Exposures: exposures})
		deps.AppendAuditCLI("item.delete", map[string]any{
			"action":                "secret.delete",
			"surface":               "cli",
			"actor_label":           deps.ActorLabel(),
			"item_name":             name,
			"outcome":               "deleted",
			"invalidated_exposures": len(exposures),
		})
	}
	payload := map[string]any{"deleted": deleted, "missing": missing}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		lead := fmt.Sprintf("Processed %d %s.", len(deleted)+len(missing), deps.CLIPlural(len(deleted)+len(missing), "secret", "secrets"))
		return deps.RenderSecretMutations(w, "Secret delete", lead, deleted, missing)
	})
}
