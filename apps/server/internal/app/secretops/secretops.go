package secretops

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/app/cmddispatch"
	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// Deps bundles every external dependency the secret subcommand handlers need.
// All fields are closure-typed so package app can wire the existing seam vars
// at call time and test overrides flow through transparently.
type Deps struct {
	// The 15 named seams from the bead description:

	// OpenVault opens an authenticated vault handle.
	OpenVault func(ctx context.Context) (*store.Handle, error)
	// ClipboardCopy copies b to the system clipboard.
	ClipboardCopy func(b []byte) error
	// UpsertItem creates or updates a vault item.
	UpsertItem func(handle *store.Handle, name string, kind store.ItemKind, value []byte, metadata store.ItemMetadata) (store.Item, error)
	// GetItem fetches a single vault item by name.
	GetItem func(handle *store.Handle, name string) (store.Item, error)
	// DeleteItem removes a vault item by name.
	DeleteItem func(handle *store.Handle, name string) error
	// ListItems returns all items in the vault.
	ListItems func(handle *store.Handle) []store.Item
	// BindItemAlias binds an item alias for the given project root.
	BindItemAlias func(handle *store.Handle, ctx context.Context, projectRoot string, itemName string) (string, error)
	// HideItemFromProject removes project bindings for an item.
	HideItemFromProject func(handle *store.Handle, ctx context.Context, projectRoot string, itemName string) ([]string, error)
	// ItemExposures returns current exposure records for an item.
	ItemExposures func(handle *store.Handle, itemName string) []store.ItemExposure
	// RevokeGrantsForItem revokes all plaintext grants for an item.
	RevokeGrantsForItem func(handle *store.Handle, itemName string) (int, error)
	// IsCharDevice reports whether f is a character device (TTY).
	IsCharDevice func(f *os.File) bool
	// RevealIsTTY reports whether the given writer is a terminal.
	RevealIsTTY func(w io.Writer) bool
	// Getwd returns the current working directory.
	Getwd func() (string, error)
	// CanonicalProjectRoot resolves a project path to its canonical form.
	CanonicalProjectRoot func(ctx context.Context, projectPath string) (string, error)
	// ResolveBindingView returns the binding view for a project path.
	ResolveBindingView func(handle *store.Handle, ctx context.Context, projectPath string) (store.Binding, []store.VisibleReference, error)

	// Additional fields required to implement the handlers:

	// NewSecretPrompt constructs a prompt helper. Package app wires this to
	// newSecretPrompt so the existing secretPrompt type and seam vars are reused.
	NewSecretPrompt func(stdin io.Reader, stdout io.Writer, stderr io.Writer) Prompt

	// EnforceSecretPlaintextPolicyInteractive enforces the plaintext policy
	// with an inline TTY confirm if needed.
	EnforceSecretPlaintextPolicyInteractive func(ctx context.Context, handle *store.Handle, itemName string, action store.PlaintextAction, stdin io.Reader, stderr io.Writer) error

	// SecretProjectContext resolves (projectRoot arg) → (canonicalRoot, inRepo, err).
	SecretProjectContext func(ctx context.Context, projectRoot string) (string, bool, error)

	// EnsureProjectBindingExplicit ensures a project binding exists, creating it if needed.
	EnsureProjectBindingExplicit func(ctx context.Context, handle *store.Handle, projectRoot string) (store.Binding, []store.VisibleReference, bool, error)

	// NoteResolvedProjectRootIfImplicit prints a notice when project root was implicitly resolved.
	NoteResolvedProjectRootIfImplicit func(fs *flag.FlagSet, jsonOutput bool, resolvedRoot string, stderr io.Writer)

	// GlobalFlagsYes returns whether --yes global flag is set.
	GlobalFlagsYes func(ctx context.Context) bool

	// GlobalFlagsJSON returns whether --json global flag is set.
	GlobalFlagsJSON func(ctx context.Context) bool

	// IsHelpArg reports whether value is a recognised help-flag spelling.
	// Wired to cmddispatch.IsHelpArg by package app.
	IsHelpArg func(value string) bool

	// PrintHelpTopic emits the help topic for args to w.
	// Wired to cmddispatch.PrintHelpTopic by package app.
	PrintHelpTopic func(w io.Writer, args []string) error

	// GlobalFlagsColorOptions returns the color options from global flags.
	GlobalFlagsColorOptions func(ctx context.Context, stdout io.Writer) ui.ColorOptions

	// ActorLabel returns a best-effort operator label for audit entries.
	ActorLabel func() string

	// AppendAuditCLI appends a CLI audit event.
	AppendAuditCLI func(eventType string, details map[string]any)

	// WriteJSONResponse writes payload as JSON to w.
	WriteJSONResponse func(w io.Writer, payload any) error

	// RenderJSONOrHuman emits JSON or human-readable output.
	RenderJSONOrHuman func(ctx context.Context, stdout io.Writer, jsonOutput bool, payload any, human func(io.Writer) error) error

	// CLIPlural returns a pluralised form of word.
	CLIPlural func(n int, singular, plural string) string

	// SecretGetJSONPayload builds the JSON payload for a secret get response.
	SecretGetJSONPayload func(metadata secrettypes.MetadataView, copied bool, reveal bool, value []byte) map[string]any

	// RenderSecretMetadata renders the human-readable secret metadata.
	RenderSecretMetadata func(w io.Writer, metadata secrettypes.MetadataView, copied bool) error

	// RenderSecretMutations renders mutation results in human-readable form.
	RenderSecretMutations func(w io.Writer, title string, lead string, values []secrettypes.MutationView, missing []string) error

	// RenderSecretListJSONOrHumanWithColor renders the secret list with color.
	RenderSecretListJSONOrHumanWithColor func(ctx context.Context, stdout io.Writer, jsonOutput bool, secrets []secrettypes.MetadataView, opts ui.ColorOptions) error

	// RenderSecretSearchJSONOrHuman renders a search result.
	RenderSecretSearchJSONOrHuman func(ctx context.Context, stdout io.Writer, jsonOutput bool, query string, total int, secrets []secrettypes.MetadataView, opts ui.ColorOptions) error

	// ExpandUserPath expands ~ in a path.
	ExpandUserPath func(path string) (string, error)

	// ResolveSecretAddCollision resolves collision policy for a name during secret add.
	ResolveSecretAddCollision func(handle *store.Handle, name string, value []byte, onConflict string, prompt Prompt) (string, []byte, string, error)

	// PromptIsInteractive reports whether the prompt's stdin is a TTY.
	PromptIsInteractive func(prompt Prompt) bool

	// NewNotFoundError constructs a user-facing "not found" error with an optional hint.
	// Package app wires this to newAppError(errCodeNotFound, msg).withHint(hint).
	NewNotFoundError func(msg string, hint string) error

	// NewFlagSet creates a new FlagSet with the given name and error handling.
	// Routing FlagSet creation through Deps ensures that the AST-based drift
	// scanner in package app sees all FlagSet registrations, because secretops/
	// source files contain no direct flag.NewFlagSet calls.
	NewFlagSet func(name string, eh flag.ErrorHandling) *flag.FlagSet
}

// Prompt is the minimal interface required by the secretops handlers.
// Package app implements this with its secretPrompt type.
type Prompt interface {
	Line(label string) (string, error)
	SecretValue(name string) ([]byte, error)
	Confirm(label string, defaultYes bool) (bool, error)
	Collision(name string) (choice string, renamed string, err error)
}

// printSecretHelp writes a minimal secret subcommand help stub. Used when
// cmddispatch.PrintHelpTopicFn is not wired (e.g. in isolated unit tests).
func printSecretHelp(w io.Writer, args []string) error {
	subcommands := []string{"add", "update", "rotate", "delete", "get", "show", "reveal", "copy", "list", "search", "diff", "expose", "hide"}
	_, err := fmt.Fprintf(w, "Usage: hasp secret <subcommand>\n\nSubcommands: %s\n", strings.Join(subcommands, ", "))
	return err
}

// isHelpArgFallback is a self-contained help-arg detector used when deps.IsHelpArg is
// not wired. Mirrors the logic in cmddispatch.IsHelpArg so the dispatcher
// works in unit-test contexts where package app's init() has not run.
func isHelpArgFallback(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "help", "-h", "--help", "-help":
		return true
	}
	return false
}

// SecretCommand is the top-level dispatcher for `hasp secret <subcommand>`.
func SecretCommand(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	isHelp := deps.IsHelpArg
	if isHelp == nil {
		isHelp = isHelpArgFallback
	}
	printHelp := deps.PrintHelpTopic
	if printHelp == nil {
		if cmddispatch.PrintHelpTopicFn != nil {
			printHelp = cmddispatch.PrintHelpTopic
		} else {
			printHelp = printSecretHelp
		}
	}
	if len(args) == 0 || isHelp(args[0]) {
		return printHelp(stdout, []string{"secret"})
	}
	if len(args) > 1 && isHelp(args[1]) {
		return printHelp(stdout, []string{"secret", args[0]})
	}
	switch args[0] {
	case "add":
		return secretAddCommand(ctx, deps, args[1:], stdin, stdout, stderr)
	case "update":
		return secretUpdateCommand(ctx, deps, args[1:], stdin, stdout, stderr)
	case "rotate":
		return secretRotateCommand(ctx, deps, args[1:], stdin, stdout, stderr)
	case "delete":
		return secretDeleteCommand(ctx, deps, args[1:], stdin, stdout, stderr)
	case "get", "retrieve":
		return secretGetCommand(ctx, deps, args[1:], stdin, stdout, stderr)
	case "show":
		return secretShowCommand(ctx, deps, args[1:], stdin, stdout, stderr)
	case "reveal":
		return secretRevealCommand(ctx, deps, args[1:], stdin, stdout, stderr)
	case "copy":
		return secretCopyCommand(ctx, deps, args[1:], stdin, stdout, stderr)
	case "list":
		return secretListCommand(ctx, deps, args[1:], stdout)
	case "search":
		return secretSearchCommand(ctx, deps, args[1:], stdout)
	case "diff":
		return secretDiffCommand(ctx, deps, args[1:], stdout)
	case "expose":
		return secretExposeCommand(ctx, deps, args[1:], stdin, stdout, stderr)
	case "hide":
		return secretHideCommand(ctx, deps, args[1:], stdin, stdout, stderr)
	default:
		candidates := []string{"add", "update", "rotate", "delete", "get", "show", "reveal", "copy", "list", "search", "diff", "expose", "hide"}
		if hint, found := closestMatch(args[0], candidates); found {
			return fmt.Errorf("unknown secret subcommand %q; did you mean: %s?", args[0], hint)
		}
		return fmt.Errorf("unknown secret subcommand %q", args[0])
	}
}
