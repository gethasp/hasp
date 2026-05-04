package app

import (
	"context"
	"flag"
	"io"
	"os"

	"github.com/gethasp/hasp/apps/server/internal/app/secretops"
	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// defaultSecretDeps builds a secretops.Deps wired to the package-level seam
// vars. Each closure reads the current value of its seam var at call time, so
// test overrides of secretClipboardFn, secretGetItemFn, etc. propagate
// transparently through the secretops handlers.
func defaultSecretDeps() secretops.Deps {
	return secretops.Deps{
		// The 15 named seams from the bead description:
		OpenVault: func(ctx context.Context) (*store.Handle, error) {
			return openVaultHandleFn(ctx)
		},
		ClipboardCopy: func(b []byte) error {
			return secretClipboardFn(b)
		},
		UpsertItem: func(handle *store.Handle, name string, kind store.ItemKind, value []byte, metadata store.ItemMetadata) (store.Item, error) {
			return secretUpsertItemFn(handle, name, kind, value, metadata)
		},
		GetItem: func(handle *store.Handle, name string) (store.Item, error) {
			return secretGetItemFn(handle, name)
		},
		DeleteItem: func(handle *store.Handle, name string) error {
			return secretDeleteItemFn(handle, name)
		},
		ListItems: func(handle *store.Handle) []store.Item {
			return secretListItemsFn(handle)
		},
		BindItemAlias: func(handle *store.Handle, ctx context.Context, projectRoot string, itemName string) (string, error) {
			return secretBindItemAliasFn(handle, ctx, projectRoot, itemName)
		},
		HideItemFromProject: func(handle *store.Handle, ctx context.Context, projectRoot string, itemName string) ([]string, error) {
			return secretHideItemFn(handle, ctx, projectRoot, itemName)
		},
		ItemExposures: func(handle *store.Handle, itemName string) []store.ItemExposure {
			return secretItemExposuresFn(handle, itemName)
		},
		RevokeGrantsForItem: func(handle *store.Handle, itemName string) (int, error) {
			return secretRevokeGrantsForItemFn(handle, itemName)
		},
		IsCharDevice: func(f *os.File) bool {
			return secretIsCharDeviceFn(f)
		},
		RevealIsTTY: func(w io.Writer) bool {
			return secretRevealIsTTYFn(w)
		},
		Getwd: func() (string, error) {
			return secretGetwdFn()
		},
		CanonicalProjectRoot: func(ctx context.Context, projectPath string) (string, error) {
			return appCanonicalProjectRootFn(ctx, projectPath)
		},
		ResolveBindingView: func(handle *store.Handle, ctx context.Context, projectPath string) (store.Binding, []store.VisibleReference, error) {
			return resolveBindingViewAppFn(handle, ctx, projectPath)
		},

		// Prompt construction: wraps the concrete *secretPrompt in the
		// secretops.Prompt interface via secretPromptAdapter.
		NewSecretPrompt: func(stdin io.Reader, stdout io.Writer, stderr io.Writer) secretops.Prompt {
			return &secretPromptAdapter{inner: newSecretPrompt(stdin, stdout, stderr)}
		},

		// Plaintext policy enforcement.
		EnforceSecretPlaintextPolicyInteractive: func(ctx context.Context, handle *store.Handle, itemName string, action store.PlaintextAction, stdin io.Reader, stderr io.Writer) error {
			return enforceSecretPlaintextPolicyInteractive(ctx, handle, itemName, action, stdin, stderr, defaultSecretPlaintextDeps())
		},

		// Project context helpers.
		SecretProjectContext:         secretProjectContext,
		EnsureProjectBindingExplicit: ensureProjectBindingExplicit,
		NoteResolvedProjectRootIfImplicit: func(fs *flag.FlagSet, jsonOutput bool, resolvedRoot string, stderr io.Writer) {
			noteResolvedProjectRootIfImplicit(fs, jsonOutput, resolvedRoot, stderr)
		},

		// Global flag accessors.
		GlobalFlagsYes: func(ctx context.Context) bool {
			return globalFlagsFromContext(ctx).yes
		},
		GlobalFlagsJSON: func(ctx context.Context) bool {
			return globalFlagsFromContext(ctx).json
		},
		GlobalFlagsColorOptions: func(ctx context.Context, stdout io.Writer) ui.ColorOptions {
			gf := globalFlagsFromContext(ctx)
			return ui.ColorOptions{
				Interactive: ui.IsInteractiveWriter(stdout),
				Disable:     gf.noColor,
				Quiet:       gf.quiet,
				Verbose:     gf.verbose,
			}
		},

		// Audit helpers.
		ActorLabel: secretActorLabel,
		AppendAuditCLI: func(eventType string, details map[string]any) {
			appendSecretAuditCLI(eventType, details)
		},

		// JSON / render helpers.
		WriteJSONResponse: writeJSONResponse,
		RenderJSONOrHuman: renderJSONOrHuman,
		CLIPlural:         cliPlural,

		SecretGetJSONPayload:                 secretGetJSONPayload,
		RenderSecretMetadata:                 renderSecretMetadata,
		RenderSecretMutations:                renderSecretMutations,
		RenderSecretListJSONOrHumanWithColor: renderSecretListJSONOrHumanWithColor,
		RenderSecretSearchJSONOrHuman:        renderSecretSearchJSONOrHuman,

		// Path utilities.
		ExpandUserPath: expandUserPath,

		// Collision resolution: wraps the package-app function so test
		// overrides of secretGetItemFn propagate.
		ResolveSecretAddCollision: func(handle *store.Handle, name string, value []byte, onConflict string, prompt secretops.Prompt) (string, []byte, string, error) {
			// Cast prompt back to *secretPrompt; package app always passes one.
			p, _ := prompt.(*secretPromptAdapter)
			var sp *secretPrompt
			if p != nil {
				sp = p.inner
			}
			return resolveSecretAddCollision(handle, name, value, onConflict, sp)
		},

		// Prompt interactivity check.
		PromptIsInteractive: func(prompt secretops.Prompt) bool {
			p, _ := prompt.(*secretPromptAdapter)
			if p == nil {
				return false
			}
			return secretPromptIsInteractive(p.inner)
		},

		// Error constructors.
		NewNotFoundError: func(msg string, hint string) error {
			return newAppError(errCodeNotFound, msg).withHint(hint)
		},

		// FlagSet factory: routing through Deps keeps secretops/ free of
		// direct flag.NewFlagSet call expressions so the AST drift scanner
		// in package app stays satisfied.
		NewFlagSet: flag.NewFlagSet,
	}
}

// secretPromptAdapter wraps *secretPrompt to implement secretops.Prompt.
// It is constructed by defaultSecretDeps().NewSecretPrompt and carries the
// concrete *secretPrompt so the ResolveSecretAddCollision and
// PromptIsInteractive closures can type-assert it back.
type secretPromptAdapter struct {
	inner *secretPrompt
}

// Ensure *secretPromptAdapter implements secretops.Prompt at compile time.
var _ secretops.Prompt = (*secretPromptAdapter)(nil)

func (a *secretPromptAdapter) Line(label string) (string, error) {
	return a.inner.line(label)
}

func (a *secretPromptAdapter) SecretValue(name string) ([]byte, error) {
	return a.inner.secretValue(name)
}

func (a *secretPromptAdapter) Confirm(label string, defaultYes bool) (bool, error) {
	return a.inner.confirm(label, defaultYes)
}

func (a *secretPromptAdapter) Collision(name string) (string, string, error) {
	return a.inner.collision(name)
}
