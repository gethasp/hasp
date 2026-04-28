package secretops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func secretAddCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := newFlagSet(deps, "secret add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", "", "")
	vaultOnly := fs.Bool("vault-only", false, "")
	onConflict := fs.String("on-conflict", "", "")
	fromStdin := fs.Bool("from-stdin", false, "")
	fromFile := fs.String("from-file", "", "")
	kindFlag := fs.String("kind", string(store.ItemKindKV), "")
	exposeFlag := fs.String("expose", "ask", "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	kind := store.ItemKind(*kindFlag)
	switch kind {
	case store.ItemKindKV, store.ItemKindFile:
	default:
		return fmt.Errorf("unknown --kind %q (expected kv or file)", *kindFlag)
	}
	if *fromFile != "" && *fromStdin {
		return errors.New("--from-file and --from-stdin are mutually exclusive")
	}
	if kind == store.ItemKindFile && *fromFile == "" && !*fromStdin {
		return errors.New("--kind file requires --from-file <path> or --from-stdin")
	}
	exposeMode := strings.ToLower(strings.TrimSpace(*exposeFlag))
	switch exposeMode {
	case "ask", "always", "never":
	default:
		return fmt.Errorf("unknown --expose %q (expected ask, always, or never)", *exposeFlag)
	}
	if *vaultOnly && exposeMode != "ask" && exposeMode != "never" {
		return errors.New("--vault-only conflicts with --expose=" + exposeMode + "; pick one")
	}
	if expandedRoot, expandErr := deps.ExpandUserPath(strings.TrimSpace(*projectRoot)); expandErr != nil {
		return fmt.Errorf("--project-root: %w", expandErr)
	} else {
		*projectRoot = expandedRoot
	}
	if *fromFile != "" {
		expandedFile, expandErr := deps.ExpandUserPath(strings.TrimSpace(*fromFile))
		if expandErr != nil {
			return fmt.Errorf("--from-file: %w", expandErr)
		}
		*fromFile = expandedFile
	}

	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}

	prompt := deps.NewSecretPrompt(stdin, stdout, stderr)
	var inputs []secretInput
	switch {
	case *fromFile != "":
		names := fs.Args()
		if len(names) != 1 {
			return errors.New("--from-file requires exactly one secret name")
		}
		raw, err := os.ReadFile(*fromFile)
		if err != nil {
			return fmt.Errorf("read --from-file: %w", err)
		}
		inputs = []secretInput{{name: names[0], value: raw}}
	case *fromStdin:
		names := fs.Args()
		if len(names) != 1 {
			return errors.New("--from-stdin requires exactly one secret name")
		}
		raw, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		// File-kind preserves trailing newlines (PEM blobs, certs); kv keeps
		// the prior shell-friendly trim so `echo abc | hasp secret add ...`
		// stores "abc" not "abc\n".
		value := raw
		if kind == store.ItemKindKV {
			value = []byte(strings.TrimRight(string(raw), "\r\n"))
		}
		inputs = []secretInput{{name: names[0], value: value}}
	default:
		inputs, err = secretAddInputs(deps, fs.Args(), prompt)
		if err != nil {
			return err
		}
	}
	targetRoot, inRepo, err := deps.SecretProjectContext(ctx, *projectRoot)
	if err != nil {
		return err
	}
	if inRepo {
		deps.NoteResolvedProjectRootIfImplicit(fs, *jsonOutput, targetRoot, stderr)
	}
	autoExpose, err := resolveSecretAddExpose(ctx, deps, inRepo, *vaultOnly, exposeMode, prompt)
	if err != nil {
		return err
	}
	if autoExpose {
		if _, _, _, err := deps.EnsureProjectBindingExplicit(ctx, handle, targetRoot); err != nil {
			return err
		}
	}

	added, err := secretAddPersistInputs(ctx, deps, handle, inputs, kind, autoExpose, targetRoot, *onConflict, prompt)
	if err != nil {
		return err
	}
	payload := map[string]any{"added": added}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return deps.RenderSecretMutations(w, "Secret add", fmt.Sprintf("Processed %d %s.", len(added), deps.CLIPlural(len(added), "secret", "secrets")), added, nil)
	})
}

// secretAddPersistInputs walks the resolved input list, applies collision
// policy, upserts each item, optionally binds it to the active repo for
// autoExpose, and appends a per-item capture audit.
func secretAddPersistInputs(ctx context.Context, deps Deps, handle *store.Handle, inputs []secretInput, kind store.ItemKind, autoExpose bool, targetRoot string, onConflict string, prompt Prompt) ([]secrettypes.MutationView, error) {
	added := make([]secrettypes.MutationView, 0, len(inputs))
	for _, input := range inputs {
		name, value, outcome, err := deps.ResolveSecretAddCollision(handle, input.name, input.value, onConflict, prompt)
		if err != nil {
			return nil, err
		}
		if outcome == "skipped" {
			added = append(added, secrettypes.MutationView{Name: input.name, NamedReference: store.NamedReference(input.name), Outcome: outcome})
			continue
		}
		item, err := deps.UpsertItem(handle, name, kind, value, store.ItemMetadata{})
		if err != nil {
			return nil, err
		}
		view := secrettypes.MutationView{Name: item.Name, NamedReference: store.NamedReference(item.Name), Kind: item.Kind, Outcome: outcome}
		if autoExpose {
			reference, err := deps.BindItemAlias(handle, ctx, targetRoot, item.Name)
			if err != nil {
				return nil, err
			}
			view.ProjectRoot = targetRoot
			view.Reference = reference
		}
		added = append(added, view)
		deps.AppendAuditCLI("capture", map[string]any{
			"action":       "secret.add",
			"surface":      "cli",
			"actor_label":  deps.ActorLabel(),
			"item_name":    item.Name,
			"item_kind":    item.Kind,
			"project_root": view.ProjectRoot,
			"reference":    view.Reference,
			"outcome":      outcome,
		})
	}
	return added, nil
}

// resolveSecretAddExpose decides whether `hasp secret add` should auto-bind
// new values to the current repo.
func resolveSecretAddExpose(ctx context.Context, deps Deps, inRepo, vaultOnly bool, mode string, prompt Prompt) (bool, error) {
	if !inRepo {
		return false, nil
	}
	if vaultOnly {
		return false, nil
	}
	switch mode {
	case "always":
		return true, nil
	case "never":
		return false, nil
	case "ask":
		if deps.GlobalFlagsYes(ctx) {
			return true, nil
		}
		if !deps.PromptIsInteractive(prompt) {
			return false, errors.New("non-interactive secret add inside a repo refuses to silently auto-bind; pass --vault-only, --expose=never to skip the bind, or --expose=always to opt in")
		}
		answer, err := prompt.Confirm("Bind new secrets to this repo automatically", true)
		if err != nil {
			return false, err
		}
		return answer, nil
	default:
		return false, fmt.Errorf("unknown --expose %q", mode)
	}
}

func secretUpdateCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := newFlagSet(deps, "secret update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	prompt := deps.NewSecretPrompt(stdin, stdout, stderr)
	inputs, err := secretUpdateInputs(deps, fs.Args(), prompt)
	if err != nil {
		return err
	}
	updated := make([]secrettypes.MutationView, 0, len(inputs))
	for _, input := range inputs {
		existing, err := deps.GetItem(handle, input.name)
		if err != nil {
			return err
		}
		item, err := deps.UpsertItem(handle, existing.Name, existing.Kind, input.value, existing.Metadata)
		if err != nil {
			return err
		}
		view := secrettypes.MutationView{
			Name:           item.Name,
			NamedReference: store.NamedReference(item.Name),
			Kind:           item.Kind,
			Outcome:        "updated",
			Exposures:      deps.ItemExposures(handle, item.Name),
		}
		updated = append(updated, view)
		deps.AppendAuditCLI("capture", map[string]any{
			"action":      "secret.update",
			"surface":     "cli",
			"actor_label": deps.ActorLabel(),
			"item_name":   item.Name,
			"item_kind":   item.Kind,
			"outcome":     "updated",
		})
	}
	payload := map[string]any{"updated": updated}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return deps.RenderSecretMutations(w, "Secret update", fmt.Sprintf("Updated %d %s.", len(updated), deps.CLIPlural(len(updated), "secret", "secrets")), updated, nil)
	})
}

func secretRotateCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := newFlagSet(deps, "secret rotate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	prompt := deps.NewSecretPrompt(stdin, stdout, stderr)
	inputs, err := secretUpdateInputs(deps, fs.Args(), prompt)
	if err != nil {
		return err
	}
	rotated := make([]secrettypes.MutationView, 0, len(inputs))
	revokedTotal := 0
	for _, input := range inputs {
		existing, err := deps.GetItem(handle, input.name)
		if err != nil {
			return err
		}
		item, err := deps.UpsertItem(handle, existing.Name, existing.Kind, input.value, existing.Metadata)
		if err != nil {
			return err
		}
		revoked, err := deps.RevokeGrantsForItem(handle, item.Name)
		if err != nil {
			return err
		}
		revokedTotal += revoked
		rotated = append(rotated, secrettypes.MutationView{
			Name:           item.Name,
			NamedReference: store.NamedReference(item.Name),
			Kind:           item.Kind,
			Outcome:        "rotated",
			Exposures:      deps.ItemExposures(handle, item.Name),
		})
		deps.AppendAuditCLI("capture", map[string]any{
			"action":          "secret.rotate",
			"surface":         "cli",
			"actor_label":     deps.ActorLabel(),
			"item_name":       item.Name,
			"item_kind":       item.Kind,
			"outcome":         "rotated",
			"revoked_grants":  revoked,
			"provider_caveat": "provider-side credential rotation remains operator responsibility",
		})
	}
	payload := map[string]any{
		"rotated":         rotated,
		"revoked_grants":  revokedTotal,
		"provider_caveat": "provider-side credential rotation remains operator responsibility",
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return deps.RenderSecretMutations(w, "Secret rotate", "Rotated local HASP values. Provider-side credential rotation remains operator responsibility.", rotated, nil)
	})
}

// secretInput holds a resolved name/value pair for secret add/update/rotate.
type secretInput struct {
	name  string
	value []byte
}

// secretAddInputs collects name/value pairs for `secret add`.
func secretAddInputs(deps Deps, args []string, prompt Prompt) ([]secretInput, error) {
	if len(args) == 0 {
		out := make([]secretInput, 0)
		for {
			name, err := prompt.Line("Key name")
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(name) == "" {
				return nil, errors.New("key name is required")
			}
			value, err := prompt.SecretValue(name)
			if err != nil {
				return nil, err
			}
			out = append(out, secretInput{name: name, value: value})
			again, err := prompt.Confirm("Add another", true)
			if err != nil {
				return nil, err
			}
			if !again {
				return out, nil
			}
		}
	}
	return secretInputsFromArgs(deps, args, prompt)
}

// secretUpdateInputs collects name/value pairs for `secret update` / `secret rotate`.
func secretUpdateInputs(deps Deps, args []string, prompt Prompt) ([]secretInput, error) {
	if len(args) == 0 {
		name, err := prompt.Line("Key name")
		if err != nil {
			return nil, err
		}
		value, err := prompt.SecretValue(name)
		if err != nil {
			return nil, err
		}
		return []secretInput{{name: name, value: value}}, nil
	}
	return secretInputsFromArgs(deps, args, prompt)
}

func secretInputsFromArgs(deps Deps, args []string, prompt Prompt) ([]secretInput, error) {
	out := make([]secretInput, 0, len(args))
	for _, arg := range args {
		name, _, ok := strings.Cut(arg, "=")
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, errors.New("secret name is required")
		}
		if ok {
			return nil, errors.New("refusing secret value on argv: use interactive prompt, --from-stdin, or --from-file (value visible in ps/history)")
		}
		prompted, err := prompt.SecretValue(name)
		if err != nil {
			return nil, err
		}
		out = append(out, secretInput{name: name, value: prompted})
	}
	return out, nil
}

func secretNameInputs(args []string, prompt Prompt, label string) ([]string, error) {
	if len(args) > 0 {
		names := make([]string, 0, len(args))
		for _, arg := range args {
			name := strings.TrimSpace(arg)
			if name == "" {
				return nil, errors.New("secret name is required")
			}
			names = append(names, name)
		}
		return names, nil
	}
	name, err := prompt.Line(label)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("secret name is required")
	}
	return []string{name}, nil
}
