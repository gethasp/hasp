package secretops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func secretExposeCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := newFlagSet(deps, "secret expose", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", "", "")
	args = reorderFlagsBeforePositionals(fs, args)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if expandedRoot, expandErr := deps.ExpandUserPath(strings.TrimSpace(*projectRoot)); expandErr != nil {
		return fmt.Errorf("--project-root: %w", expandErr)
	} else {
		*projectRoot = expandedRoot
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
	targetRoot, inRepo, err := deps.SecretProjectContext(ctx, *projectRoot)
	if err != nil {
		return err
	}
	if !inRepo {
		return errors.New("secret expose requires a git repo context or --project-root")
	}
	deps.NoteResolvedProjectRootIfImplicit(fs, *jsonOutput, targetRoot, stderr)
	if _, _, _, err := deps.EnsureProjectBindingExplicit(ctx, handle, targetRoot); err != nil {
		return err
	}
	exposed := make([]secrettypes.MutationView, 0, len(names))
	for _, name := range names {
		if _, err := deps.GetItem(handle, name); err != nil {
			return err
		}
		existingRef := existingExposureReference(deps.ItemExposures(handle, name), targetRoot)
		reference, err := deps.BindItemAlias(handle, ctx, targetRoot, name)
		if err != nil {
			return err
		}
		outcome := "exposed"
		if existingRef != "" {
			outcome = "already_exposed"
		}
		exposed = append(exposed, secrettypes.MutationView{Name: name, NamedReference: store.NamedReference(name), Outcome: outcome, ProjectRoot: targetRoot, Reference: reference})
		deps.AppendAuditCLI("binding.alias_bind", map[string]any{
			"action":       "secret.expose",
			"surface":      "cli",
			"actor_label":  deps.ActorLabel(),
			"item_name":    name,
			"project_root": targetRoot,
			"reference":    reference,
			"outcome":      outcome,
		})
	}
	payload := map[string]any{"exposed": exposed}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return deps.RenderSecretMutations(w, "Secret expose", fmt.Sprintf("Processed %d %s.", len(exposed), deps.CLIPlural(len(exposed), "secret", "secrets")), exposed, nil)
	})
}

func secretHideCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := newFlagSet(deps, "secret hide", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", "", "")
	args = reorderFlagsBeforePositionals(fs, args)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if expandedRoot, expandErr := deps.ExpandUserPath(strings.TrimSpace(*projectRoot)); expandErr != nil {
		return fmt.Errorf("--project-root: %w", expandErr)
	} else {
		*projectRoot = expandedRoot
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
	targetRoot, inRepo, err := deps.SecretProjectContext(ctx, *projectRoot)
	if err != nil {
		return err
	}
	if !inRepo {
		return errors.New("secret hide requires a git repo context or --project-root")
	}
	deps.NoteResolvedProjectRootIfImplicit(fs, *jsonOutput, targetRoot, stderr)
	hidden := make([]secrettypes.MutationView, 0, len(names))
	for _, name := range names {
		removed, err := deps.HideItemFromProject(handle, ctx, targetRoot, name)
		if err != nil {
			return err
		}
		outcome := "already_hidden"
		reference := ""
		if len(removed) > 0 {
			outcome = "hidden"
			reference = strings.Join(removed, ",")
		}
		hidden = append(hidden, secrettypes.MutationView{Name: name, NamedReference: store.NamedReference(name), Outcome: outcome, ProjectRoot: targetRoot, Reference: reference})
		deps.AppendAuditCLI("binding.alias_hide", map[string]any{
			"action":       "secret.hide",
			"surface":      "cli",
			"actor_label":  deps.ActorLabel(),
			"item_name":    name,
			"project_root": targetRoot,
			"references":   removed,
			"outcome":      outcome,
		})
	}
	payload := map[string]any{"hidden": hidden}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return deps.RenderSecretMutations(w, "Secret hide", fmt.Sprintf("Processed %d %s.", len(hidden), deps.CLIPlural(len(hidden), "secret", "secrets")), hidden, nil)
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
