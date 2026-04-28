package app

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/app/ttyutil"
	"github.com/gethasp/hasp/apps/server/internal/app/ui"
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
	case "show":
		return secretShowCommand(ctx, args[1:], stdin, stdout, stderr)
	case "reveal":
		return secretRevealCommand(ctx, args[1:], stdin, stdout, stderr)
	case "copy":
		return secretCopyCommand(ctx, args[1:], stdin, stdout, stderr)
	case "list":
		return secretListCommand(ctx, args[1:], stdout)
	case "search":
		return secretSearchCommand(ctx, args[1:], stdout)
	case "diff":
		return secretDiffCommand(ctx, args[1:], stdout)
	case "expose":
		return secretExposeCommand(ctx, args[1:], stdin, stdout, stderr)
	case "hide":
		return secretHideCommand(ctx, args[1:], stdin, stdout, stderr)
	default:
		candidates := []string{"add", "update", "rotate", "delete", "get", "show", "reveal", "copy", "list", "search", "diff", "expose", "hide"}
		if hint, found := closestMatch(args[0], candidates); found {
			return fmt.Errorf("unknown secret subcommand %q; did you mean: %s?", args[0], hint)
		}
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
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
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
	if expandedRoot, expandErr := expandUserPath(strings.TrimSpace(*projectRoot)); expandErr != nil {
		return fmt.Errorf("--project-root: %w", expandErr)
	} else {
		*projectRoot = expandedRoot
	}
	if *fromFile != "" {
		expandedFile, expandErr := expandUserPath(strings.TrimSpace(*fromFile))
		if expandErr != nil {
			return fmt.Errorf("--from-file: %w", expandErr)
		}
		*fromFile = expandedFile
	}

	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}

	prompt := newSecretPrompt(stdin, stdout, stderr)
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
		inputs, err = secretAddInputs(fs.Args(), prompt)
		if err != nil {
			return err
		}
	}
	targetRoot, inRepo, err := secretProjectContext(ctx, *projectRoot)
	if err != nil {
		return err
	}
	if inRepo {
		noteResolvedProjectRootIfImplicit(fs, *jsonOutput, targetRoot, stderr)
	}
	autoExpose, err := resolveSecretAddExpose(ctx, inRepo, *vaultOnly, exposeMode, prompt)
	if err != nil {
		return err
	}
	if autoExpose {
		if _, _, _, err := ensureProjectBindingExplicit(ctx, handle, targetRoot); err != nil {
			return err
		}
	}

	added, err := secretAddPersistInputs(ctx, handle, inputs, kind, autoExpose, targetRoot, *onConflict, prompt)
	if err != nil {
		return err
	}
	payload := map[string]any{"added": added}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSecretMutations(w, "Secret add", fmt.Sprintf("Processed %d %s.", len(added), cliPlural(len(added), "secret", "secrets")), added, nil)
	})
}

// secretAddPersistInputs walks the resolved input list, applies collision
// policy, upserts each item, optionally binds it to the active repo for
// autoExpose, and appends a per-item capture audit. Splitting this off
// keeps secretAddCommand focused on flag parsing and input collection.
func secretAddPersistInputs(ctx context.Context, handle *store.Handle, inputs []secretInput, kind store.ItemKind, autoExpose bool, targetRoot string, onConflict string, prompt *secretPrompt) ([]secretMutationView, error) {
	added := make([]secretMutationView, 0, len(inputs))
	for _, input := range inputs {
		name, value, outcome, err := resolveSecretAddCollision(handle, input.name, input.value, onConflict, prompt)
		if err != nil {
			return nil, err
		}
		if outcome == "skipped" {
			added = append(added, secretMutationView{Name: input.name, NamedReference: store.NamedReference(input.name), Outcome: outcome})
			continue
		}
		item, err := secretUpsertItemFn(handle, name, kind, value, store.ItemMetadata{})
		if err != nil {
			return nil, err
		}
		view := secretMutationView{Name: item.Name, NamedReference: store.NamedReference(item.Name), Kind: item.Kind, Outcome: outcome}
		if autoExpose {
			reference, err := secretBindItemAliasFn(handle, ctx, targetRoot, item.Name)
			if err != nil {
				return nil, err
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
	return added, nil
}

// resolveSecretAddExpose decides whether `hasp secret add` should auto-bind
// new values to the current repo. The default ("ask") prompts in interactive
// mode and refuses in non-interactive mode so scripts can never silently
// bind a fresh secret to a repo the operator never named. When the ambient
// --yes flag is set (hasp-yat2) the prompt is skipped and the default answer
// (true) is taken.
func resolveSecretAddExpose(ctx context.Context, inRepo, vaultOnly bool, mode string, prompt *secretPrompt) (bool, error) {
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
		if globalFlagsFromContext(ctx).yes {
			return true, nil
		}
		if !secretPromptIsInteractive(prompt) {
			return false, errors.New("non-interactive secret add inside a repo refuses to silently auto-bind; pass --vault-only, --expose=never to skip the bind, or --expose=always to opt in")
		}
		answer, err := prompt.confirm("Bind new secrets to this repo automatically", true)
		if err != nil {
			return false, err
		}
		return answer, nil
	default:
		return false, fmt.Errorf("unknown --expose %q", mode)
	}
}

// secretPromptIsInteractive returns true when prompt.stdin is a tty char
// device. Tests pass bytes.Buffer / strings.Reader for stdin, which falls
// through to false — exactly the script path the new gate guards.
func secretPromptIsInteractive(prompt *secretPrompt) bool {
	if prompt == nil {
		return false
	}
	file, ok := ttyutil.StdinFile(prompt.stdin)
	if !ok {
		return false
	}
	return secretIsCharDeviceFn(file)
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
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
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
		if !*assumeYes && !globalFlagsFromContext(ctx).yes {
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
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		lead := fmt.Sprintf("Processed %d %s.", len(deleted)+len(missing), cliPlural(len(deleted)+len(missing), "secret", "secrets"))
		return renderSecretMutations(w, "Secret delete", lead, deleted, missing)
	})
}

func secretGetCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretGetWithMode(ctx, args, "auto", stdin, stdout, stderr)
}

func secretShowCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretGetWithMode(ctx, args, "show", stdin, stdout, stderr)
}

func secretRevealCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretGetWithMode(ctx, args, "reveal", stdin, stdout, stderr)
}

func secretCopyCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretGetWithMode(ctx, args, "copy", stdin, stdout, stderr)
}

// secretGetWithMode powers `secret show|reveal|copy` (intent-fixed) and
// `secret get|retrieve` (legacy, dispatch via --reveal/--copy flags). Modes
// other than "auto" reject the legacy flags so the verb stays the source of
// truth.
func secretGetWithMode(ctx context.Context, args []string, mode string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("secret "+mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	reveal := fs.Bool("reveal", false, "")
	copyValue := fs.Bool("copy", false, "")
	// --newline / --no-newline control trailing newline on raw (non-JSON) reveal
	// output independently of TTY detection.
	newlineFlag := fs.Bool("newline", false, "")
	noNewlineFlag := fs.Bool("no-newline", false, "")
	// Allow flags to appear after positional args (e.g. "NAME --reveal").
	args = reorderFlagsBeforePositionals(args)
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
		if errors.Is(err, store.ErrItemNotFound) {
			return newAppError(errCodeNotFound, fmt.Sprintf("secret %q not found in vault", names[0])).
				withHint("run `hasp list` to see managed secret names")
		}
		return err
	}
	metadata := secretMetadataView{
		Name:           item.Name,
		NamedReference: store.NamedReference(item.Name),
		Kind:           item.Kind,
		CreatedAt:      item.CreatedAt.Format(secrettypes.TimeRFC3339),
		UpdatedAt:      item.UpdatedAt.Format(secrettypes.TimeRFC3339),
		Exposures:      secretItemExposuresFn(handle, item.Name),
	}
	switch {
	case *reveal:
		if err := enforceSecretPlaintextPolicyInteractive(ctx, handle, item.Name, store.PlaintextReveal, stdin, stderr, defaultSecretPlaintextDeps()); err != nil {
			return err
		}
		appendSecretAuditCLI(audit.EventRead, map[string]any{
			"action":      "secret.get.reveal",
			"surface":     "cli",
			"actor_label": secretActorLabel(),
			"item_name":   item.Name,
			"outcome":     "revealed",
		})
		if *jsonOutput || globalFlagsFromContext(ctx).json {
			return writeJSONResponse(stdout, secretGetJSONPayload(metadata, false, true, item.Value))
		}
		if _, err := stdout.Write(item.Value); err != nil {
			return err
		}
		// Trailing-newline policy (hasp-jx3r):
		//   --newline    → always append (opt-in for scripts that need it)
		//   --no-newline → never append (defensive override for piped use)
		//   default      → append only when stdout is a TTY (clean shell prompt
		//                  without polluting pbcopy/xclip pipes)
		if item.Kind == store.ItemKindKV {
			appendNL := false
			switch {
			case *noNewlineFlag:
				appendNL = false
			case *newlineFlag:
				appendNL = true
			default:
				appendNL = secretRevealIsTTYFn(stdout)
			}
			if appendNL {
				_, err = fmt.Fprintln(stdout)
				return err
			}
		}
		return nil
	case *copyValue:
		if err := enforceSecretPlaintextPolicyInteractive(ctx, handle, item.Name, store.PlaintextCopy, stdin, stderr, defaultSecretPlaintextDeps()); err != nil {
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
		return renderJSONOrHuman(ctx, stdout, *jsonOutput, secretGetJSONPayload(metadata, true, false, nil), func(w io.Writer) error {
			return renderSecretMetadata(w, metadata, true)
		})
	default:
		return renderJSONOrHuman(ctx, stdout, *jsonOutput, secretGetJSONPayload(metadata, false, false, nil), func(w io.Writer) error {
			return renderSecretMetadata(w, metadata, false)
		})
	}
}

// secretSearchCommand filters the vault inventory by a case-insensitive
// substring match on the item name. It exposes the same shape as
// secretListCommand (metadata only — never values) so JSON consumers can
// reuse their list-handling code paths.
//
// Unlike secretListCommand, the search result distinguishes "no matches for
// this filter" (vault has items but none matched) from "vault is empty". The
// JSON payload always includes total and match_count so callers can tell the
// two apart without parsing human text.
func secretSearchCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("secret search", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hasp secret search <substr> [--json]")
	}
	query := strings.ToLower(strings.TrimSpace(fs.Arg(0)))
	if query == "" {
		return errors.New("usage: hasp secret search <substr> [--json]")
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	items := secretListItemsFn(handle)
	total := len(items)
	secrets := make([]secretMetadataView, 0, len(items))
	for _, item := range items {
		if !strings.Contains(strings.ToLower(item.Name), query) {
			continue
		}
		secrets = append(secrets, secretMetadataView{
			Name:           item.Name,
			NamedReference: store.NamedReference(item.Name),
			Kind:           item.Kind,
			CreatedAt:      item.CreatedAt.Format(secrettypes.TimeRFC3339),
			UpdatedAt:      item.UpdatedAt.Format(secrettypes.TimeRFC3339),
			Exposures:      secretItemExposuresFn(handle, item.Name),
		})
	}
	gf := globalFlagsFromContext(ctx)
	opts := ui.ColorOptions{Interactive: ui.IsInteractiveWriter(stdout), Disable: gf.noColor, Quiet: gf.quiet, Verbose: gf.verbose}
	return renderSecretSearchJSONOrHuman(ctx, stdout, *jsonOutput, fs.Arg(0), total, secrets, opts)
}

// secretDiffCommand compares a candidate .env file against the vault and
// reports each KV name in one of four buckets: same (value matches),
// changed (value differs), missing (in vault but absent from .env),
// extra (in .env but absent from vault). Values are read internally to
// classify but never written to stdout — this command is safe to pipe
// into review tooling.
func secretDiffCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("secret diff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hasp secret diff <path> [--json]")
	}
	path := strings.TrimSpace(fs.Arg(0))
	if path == "" {
		return errors.New("usage: hasp secret diff <path> [--json]")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	candidate, err := parseDotEnvForDiff(bytes.NewReader(data))
	if err != nil {
		return err
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	vault := map[string]string{}
	for _, item := range secretListItemsFn(handle) {
		if item.Kind != store.ItemKindKV {
			continue
		}
		full, err := secretGetItemFn(handle, item.Name)
		if err != nil {
			return err
		}
		vault[item.Name] = string(full.Value)
	}
	same := []string{}
	changed := []string{}
	missing := []string{}
	extra := []string{}
	for name, vaultValue := range vault {
		candidateValue, ok := candidate[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		if candidateValue == vaultValue {
			same = append(same, name)
		} else {
			changed = append(changed, name)
		}
	}
	for name := range candidate {
		if _, ok := vault[name]; !ok {
			extra = append(extra, name)
		}
	}
	sort.Strings(same)
	sort.Strings(changed)
	sort.Strings(missing)
	sort.Strings(extra)
	payload := map[string]any{
		"same":    same,
		"changed": changed,
		"missing": missing,
		"extra":   extra,
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSecretDiff(w, path, same, changed, missing, extra)
	})
}

// parseDotEnvForDiff extracts name→value pairs from a .env reader using
// the same lexical rules as previewEnvImportReader so a diff and a
// subsequent import see the same keys with the same effective values.
func parseDotEnvForDiff(reader io.Reader) (map[string]string, error) {
	out := map[string]string{}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("invalid env line %q", line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		}
		out[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan env file: %w", err)
	}
	return out, nil
}

func renderSecretDiff(w io.Writer, path string, same, changed, missing, extra []string) error {
	if _, err := fmt.Fprintf(w, "Secret diff vs %s\n", path); err != nil {
		return err
	}
	for _, bucket := range []struct {
		label string
		names []string
	}{
		{"same", same},
		{"changed", changed},
		{"missing", missing},
		{"extra", extra},
	} {
		joined := strings.Join(bucket.names, ", ")
		if _, err := fmt.Fprintf(w, "  %-7s (%d): %s\n", bucket.label, len(bucket.names), joined); err != nil {
			return err
		}
	}
	return nil
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
			CreatedAt:      item.CreatedAt.Format(secrettypes.TimeRFC3339),
			UpdatedAt:      item.UpdatedAt.Format(secrettypes.TimeRFC3339),
			Exposures:      secretItemExposuresFn(handle, item.Name),
		})
	}
	gf := globalFlagsFromContext(ctx)
	opts := ui.ColorOptions{Interactive: ui.IsInteractiveWriter(stdout), Disable: gf.noColor, Quiet: gf.quiet, Verbose: gf.verbose}
	return renderSecretListJSONOrHumanWithColor(ctx, stdout, *jsonOutput, secrets, opts)
}

func secretExposeCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("secret expose", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if expandedRoot, expandErr := expandUserPath(strings.TrimSpace(*projectRoot)); expandErr != nil {
		return fmt.Errorf("--project-root: %w", expandErr)
	} else {
		*projectRoot = expandedRoot
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
	noteResolvedProjectRootIfImplicit(fs, *jsonOutput, targetRoot, stderr)
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
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
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
	if expandedRoot, expandErr := expandUserPath(strings.TrimSpace(*projectRoot)); expandErr != nil {
		return fmt.Errorf("--project-root: %w", expandErr)
	} else {
		*projectRoot = expandedRoot
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
	noteResolvedProjectRootIfImplicit(fs, *jsonOutput, targetRoot, stderr)
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
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSecretMutations(w, "Secret hide", fmt.Sprintf("Processed %d %s.", len(hidden), cliPlural(len(hidden), "secret", "secrets")), hidden, nil)
	})
}

// reorderFlagsBeforePositionals moves --flag style arguments before positional
// arguments so that Go's flag package (which stops at the first non-flag arg)
// can parse flags that appear anywhere in the argument list.
func reorderFlagsBeforePositionals(args []string) []string {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		} else {
			positionals = append(positionals, a)
		}
	}
	return append(flags, positionals...)
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
