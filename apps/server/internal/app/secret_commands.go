package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func secretCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		return printHelpTopic(stdout, []string{"secret"})
	}
	if len(args) > 1 && isHelpArg(args[1]) {
		return printHelpTopic(stdout, []string{"secret", args[0]})
	}
	switch args[0] {
	case "add":
		return secretAddCommand(ctx, args[1:], stdin, stdout, stderr)
	case "update":
		return secretUpdateCommand(ctx, args[1:], stdin, stdout, stderr)
	case "rotate":
		return secretRotateCommand(ctx, args[1:], stdin, stdout, stderr)
	case "delete":
		return secretDeleteCommand(ctx, args[1:], stdin, stdout, stderr)
	case "get", "retrieve":
		return secretGetCommand(ctx, args[1:], stdin, stdout, stderr)
	case "list":
		return secretListCommand(ctx, args[1:], stdout)
	case "expose":
		return secretExposeCommand(ctx, args[1:], stdin, stdout, stderr)
	case "hide":
		return secretHideCommand(ctx, args[1:], stdin, stdout, stderr)
	default:
		return fmt.Errorf("unknown secret subcommand %q", args[0])
	}
}

func secretRotateCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("secret rotate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	prompt := newSecretPrompt(stdin, stdout, stderr)
	inputs, err := secretUpdateInputs(fs.Args(), prompt)
	if err != nil {
		return err
	}
	rotated := make([]secretMutationView, 0, len(inputs))
	revokedTotal := 0
	for _, input := range inputs {
		existing, err := secretGetItemFn(handle, input.name)
		if err != nil {
			return err
		}
		item, err := secretUpsertItemFn(handle, existing.Name, existing.Kind, input.value, existing.Metadata)
		if err != nil {
			return err
		}
		revoked, err := secretRevokeGrantsForItemFn(handle, item.Name)
		if err != nil {
			return err
		}
		revokedTotal += revoked
		rotated = append(rotated, secretMutationView{
			Name:           item.Name,
			NamedReference: store.NamedReference(item.Name),
			Kind:           item.Kind,
			Outcome:        "rotated",
			Exposures:      secretItemExposuresFn(handle, item.Name),
		})
		appendSecretAuditCLI(audit.EventCapture, map[string]any{
			"action":          "secret.rotate",
			"surface":         "cli",
			"actor_label":     secretActorLabel(),
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
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSecretMutations(w, "Secret rotate", "Rotated local HASP values. Provider-side credential rotation remains operator responsibility.", rotated, nil)
	})
}

func secretAddCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("secret add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", "", "")
	vaultOnly := fs.Bool("vault-only", false, "")
	onConflict := fs.String("on-conflict", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	prompt := newSecretPrompt(stdin, stdout, stderr)
	inputs, err := secretAddInputs(fs.Args(), prompt)
	if err != nil {
		return err
	}
	targetRoot, inRepo, err := secretProjectContext(ctx, *projectRoot)
	if err != nil {
		return err
	}
	autoExpose := inRepo && !*vaultOnly
	if autoExpose {
		if _, _, _, err := ensureProjectBindingExplicit(ctx, handle, targetRoot); err != nil {
			return err
		}
	}

	added := make([]secretMutationView, 0, len(inputs))
	for _, input := range inputs {
		name, value, outcome, err := resolveSecretAddCollision(handle, input.name, input.value, *onConflict, prompt)
		if err != nil {
			return err
		}
		if outcome == "skipped" {
			added = append(added, secretMutationView{Name: input.name, NamedReference: store.NamedReference(input.name), Outcome: outcome})
			continue
		}
		item, err := secretUpsertItemFn(handle, name, store.ItemKindKV, value, store.ItemMetadata{})
		if err != nil {
			return err
		}
		view := secretMutationView{Name: item.Name, NamedReference: store.NamedReference(item.Name), Kind: item.Kind, Outcome: outcome}
		if autoExpose {
			reference, err := secretBindItemAliasFn(handle, ctx, targetRoot, item.Name)
			if err != nil {
				return err
			}
			view.ProjectRoot = targetRoot
			view.Reference = reference
		}
		added = append(added, view)
		appendSecretAuditCLI(audit.EventCapture, map[string]any{
			"action":       "secret.add",
			"surface":      "cli",
			"actor_label":  secretActorLabel(),
			"item_name":    item.Name,
			"item_kind":    item.Kind,
			"project_root": view.ProjectRoot,
			"reference":    view.Reference,
			"outcome":      outcome,
		})
	}
	payload := map[string]any{"added": added}
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSecretMutations(w, "Secret add", fmt.Sprintf("Processed %d %s.", len(added), cliPlural(len(added), "secret", "secrets")), added, nil)
	})
}

func secretUpdateCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("secret update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	prompt := newSecretPrompt(stdin, stdout, stderr)
	inputs, err := secretUpdateInputs(fs.Args(), prompt)
	if err != nil {
		return err
	}
	updated := make([]secretMutationView, 0, len(inputs))
	for _, input := range inputs {
		existing, err := secretGetItemFn(handle, input.name)
		if err != nil {
			return err
		}
		item, err := secretUpsertItemFn(handle, existing.Name, existing.Kind, input.value, existing.Metadata)
		if err != nil {
			return err
		}
		view := secretMutationView{
			Name:           item.Name,
			NamedReference: store.NamedReference(item.Name),
			Kind:           item.Kind,
			Outcome:        "updated",
			Exposures:      secretItemExposuresFn(handle, item.Name),
		}
		updated = append(updated, view)
		appendSecretAuditCLI(audit.EventCapture, map[string]any{
			"action":      "secret.update",
			"surface":     "cli",
			"actor_label": secretActorLabel(),
			"item_name":   item.Name,
			"item_kind":   item.Kind,
			"outcome":     "updated",
		})
	}
	payload := map[string]any{"updated": updated}
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSecretMutations(w, "Secret update", fmt.Sprintf("Updated %d %s.", len(updated), cliPlural(len(updated), "secret", "secrets")), updated, nil)
	})
}

func secretDeleteCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("secret delete", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	assumeYes := fs.Bool("yes", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	prompt := newSecretPrompt(stdin, stdout, stderr)
	names, err := secretNameInputs(fs.Args(), prompt, "Key name")
	if err != nil {
		return err
	}
	deleted := make([]secretMutationView, 0, len(names))
	missing := make([]string, 0)
	for _, name := range names {
		exposures := secretItemExposuresFn(handle, name)
		if !*assumeYes {
			ok, err := prompt.confirm(fmt.Sprintf("Delete %s", name), false)
			if err != nil {
				return err
			}
			if !ok {
				missing = append(missing, name)
				continue
			}
		}
		if err := secretDeleteItemFn(handle, name); err != nil {
			if errors.Is(err, store.ErrItemNotFound) {
				missing = append(missing, name)
				continue
			}
			return err
		}
		deleted = append(deleted, secretMutationView{Name: name, NamedReference: store.NamedReference(name), Outcome: "deleted", Exposures: exposures})
		appendSecretAuditCLI("item.delete", map[string]any{
			"action":                "secret.delete",
			"surface":               "cli",
			"actor_label":           secretActorLabel(),
			"item_name":             name,
			"outcome":               "deleted",
			"invalidated_exposures": len(exposures),
		})
	}
	payload := map[string]any{"deleted": deleted, "missing": missing}
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		lead := fmt.Sprintf("Processed %d %s.", len(deleted)+len(missing), cliPlural(len(deleted)+len(missing), "secret", "secrets"))
		return renderSecretMutations(w, "Secret delete", lead, deleted, missing)
	})
}

func secretGetCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("secret get", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	reveal := fs.Bool("reveal", false, "")
	copyValue := fs.Bool("copy", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *reveal && *copyValue {
		return errors.New("choose either --reveal or --copy")
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	prompt := newSecretPrompt(stdin, stdout, stderr)
	names, err := secretNameInputs(fs.Args(), prompt, "Key name")
	if err != nil {
		return err
	}
	if len(names) != 1 {
		return errors.New("secret get expects exactly one secret name")
	}
	item, err := secretGetItemFn(handle, names[0])
	if err != nil {
		return err
	}
	metadata := secretMetadataView{
		Name:           item.Name,
		NamedReference: store.NamedReference(item.Name),
		Kind:           item.Kind,
		CreatedAt:      item.CreatedAt.Format(timeRFC3339),
		UpdatedAt:      item.UpdatedAt.Format(timeRFC3339),
		Exposures:      secretItemExposuresFn(handle, item.Name),
	}
	switch {
	case *reveal:
		if err := enforceSecretPlaintextPolicy(ctx, handle, item.Name, store.PlaintextReveal); err != nil {
			return err
		}
		appendSecretAuditCLI(audit.EventRead, map[string]any{
			"action":      "secret.get.reveal",
			"surface":     "cli",
			"actor_label": secretActorLabel(),
			"item_name":   item.Name,
			"outcome":     "revealed",
		})
		if *jsonOutput {
			return json.NewEncoder(stdout).Encode(secretGetJSONPayload(metadata, false, true, item.Value))
		}
		if _, err := stdout.Write(item.Value); err != nil {
			return err
		}
		if item.Kind == store.ItemKindKV {
			_, err = fmt.Fprintln(stdout)
			return err
		}
		return nil
	case *copyValue:
		if err := enforceSecretPlaintextPolicy(ctx, handle, item.Name, store.PlaintextCopy); err != nil {
			return err
		}
		if err := secretClipboardFn(item.Value); err != nil {
			return err
		}
		appendSecretAuditCLI(audit.EventRead, map[string]any{
			"action":      "secret.get.copy",
			"surface":     "cli",
			"actor_label": secretActorLabel(),
			"item_name":   item.Name,
			"outcome":     "copied",
		})
		return renderJSONOrHuman(stdout, *jsonOutput, secretGetJSONPayload(metadata, true, false, nil), func(w io.Writer) error {
			return renderSecretMetadata(w, metadata, true)
		})
	default:
		return renderJSONOrHuman(stdout, *jsonOutput, secretGetJSONPayload(metadata, false, false, nil), func(w io.Writer) error {
			return renderSecretMetadata(w, metadata, false)
		})
	}
}

func secretListCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("secret list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	items := secretListItemsFn(handle)
	secrets := make([]secretMetadataView, 0, len(items))
	for _, item := range items {
		secrets = append(secrets, secretMetadataView{
			Name:           item.Name,
			NamedReference: store.NamedReference(item.Name),
			Kind:           item.Kind,
			CreatedAt:      item.CreatedAt.Format(timeRFC3339),
			UpdatedAt:      item.UpdatedAt.Format(timeRFC3339),
			Exposures:      secretItemExposuresFn(handle, item.Name),
		})
	}
	return renderSecretListJSONOrHuman(stdout, *jsonOutput, secrets)
}

func secretExposeCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("secret expose", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	prompt := newSecretPrompt(stdin, stdout, stderr)
	names, err := secretNameInputs(fs.Args(), prompt, "Key name")
	if err != nil {
		return err
	}
	targetRoot, inRepo, err := secretProjectContext(ctx, *projectRoot)
	if err != nil {
		return err
	}
	if !inRepo {
		return errors.New("secret expose requires a git repo context or --project-root")
	}
	if _, _, _, err := ensureProjectBindingExplicit(ctx, handle, targetRoot); err != nil {
		return err
	}
	exposed := make([]secretMutationView, 0, len(names))
	for _, name := range names {
		if _, err := secretGetItemFn(handle, name); err != nil {
			return err
		}
		existingRef := existingExposureReference(secretItemExposuresFn(handle, name), targetRoot)
		reference, err := secretBindItemAliasFn(handle, ctx, targetRoot, name)
		if err != nil {
			return err
		}
		outcome := "exposed"
		if existingRef != "" {
			outcome = "already_exposed"
		}
		exposed = append(exposed, secretMutationView{Name: name, NamedReference: store.NamedReference(name), Outcome: outcome, ProjectRoot: targetRoot, Reference: reference})
		appendSecretAuditCLI("binding.alias_bind", map[string]any{
			"action":       "secret.expose",
			"surface":      "cli",
			"actor_label":  secretActorLabel(),
			"item_name":    name,
			"project_root": targetRoot,
			"reference":    reference,
			"outcome":      outcome,
		})
	}
	payload := map[string]any{"exposed": exposed}
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSecretMutations(w, "Secret expose", fmt.Sprintf("Processed %d %s.", len(exposed), cliPlural(len(exposed), "secret", "secrets")), exposed, nil)
	})
}

func secretHideCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("secret hide", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	prompt := newSecretPrompt(stdin, stdout, stderr)
	names, err := secretNameInputs(fs.Args(), prompt, "Key name")
	if err != nil {
		return err
	}
	targetRoot, inRepo, err := secretProjectContext(ctx, *projectRoot)
	if err != nil {
		return err
	}
	if !inRepo {
		return errors.New("secret hide requires a git repo context or --project-root")
	}
	hidden := make([]secretMutationView, 0, len(names))
	for _, name := range names {
		removed, err := secretHideItemFn(handle, ctx, targetRoot, name)
		if err != nil {
			return err
		}
		outcome := "already_hidden"
		reference := ""
		if len(removed) > 0 {
			outcome = "hidden"
			reference = strings.Join(removed, ",")
		}
		hidden = append(hidden, secretMutationView{Name: name, NamedReference: store.NamedReference(name), Outcome: outcome, ProjectRoot: targetRoot, Reference: reference})
		appendSecretAuditCLI("binding.alias_hide", map[string]any{
			"action":       "secret.hide",
			"surface":      "cli",
			"actor_label":  secretActorLabel(),
			"item_name":    name,
			"project_root": targetRoot,
			"references":   removed,
			"outcome":      outcome,
		})
	}
	payload := map[string]any{"hidden": hidden}
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSecretMutations(w, "Secret hide", fmt.Sprintf("Processed %d %s.", len(hidden), cliPlural(len(hidden), "secret", "secrets")), hidden, nil)
	})
}

func existingExposureReference(exposures []store.ItemExposure, projectRoot string) string {
	for _, exposure := range exposures {
		if exposure.ProjectRoot == projectRoot {
			return exposure.Reference
		}
	}
	return ""
}

func ensureProjectBindingExplicit(ctx context.Context, handle *store.Handle, projectRoot string) (store.Binding, []store.VisibleReference, bool, error) {
	binding, visible, err := resolveBindingViewAppFn(handle, ctx, projectRoot)
	if err != nil {
		return store.Binding{}, nil, false, err
	}
	if binding.ID != "" {
		return binding, visible, false, nil
	}
	defaults, err := loadProjectDefaults()
	if err != nil {
		return store.Binding{}, nil, false, err
	}
	root, err := appCanonicalProjectRootFn(ctx, projectRoot)
	if err != nil {
		return store.Binding{}, nil, false, err
	}
	if !pathLooksLikeGitRepo(root) {
		return store.Binding{}, nil, false, fmt.Errorf("project %q is not a git repo", projectRoot)
	}
	installHooks := defaults.AutoInstallHooks && pathLooksLikeGitRepo(root)
	if _, err := bindProject(ctx, handle, root, cloneAliasSet(binding.Aliases), defaults.DefaultPolicy, installHooks); err != nil {
		return store.Binding{}, nil, false, err
	}
	binding, visible, err = resolveBindingViewAppFn(handle, ctx, root)
	return binding, visible, true, err
}

func secretProjectContext(ctx context.Context, projectRoot string) (string, bool, error) {
	path := strings.TrimSpace(projectRoot)
	if path == "" {
		cwd, err := secretGetwdFn()
		if err != nil {
			return "", false, err
		}
		path = cwd
	}
	root, err := appCanonicalProjectRootFn(ctx, path)
	if err != nil {
		return "", false, err
	}
	return root, pathLooksLikeGitRepo(root), nil
}
