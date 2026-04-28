package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/auditlog"
	"github.com/gethasp/hasp/apps/server/internal/app/cmddispatch"
	"github.com/gethasp/hasp/apps/server/internal/app/vaultaccess"
	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/redactor"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// Audit log seams kept package-local for backward test compatibility — the
// underlying state and helpers now live in package auditlog. Tests inside
// package app keep overriding these names; the init() below pipes the
// auditlog seams through these vars so test mutations of newAuditLogFn /
// auditEventsFn flow into auditlog.Append calls made from anywhere.
var newAuditLogFn = audit.New
var auditEventsFn = (*audit.Log).Events

func init() {
	auditlog.NewLogFn = func() (*audit.Log, error) { return newAuditLogFn() }
	auditlog.EventsFn = func(log *audit.Log) ([]audit.Event, error) { return auditEventsFn(log) }
	auditlog.CurrentUserFn = func() (*user.User, error) { return secretCurrentUserFn() }

	// Closure-indirection registration for vaultaccess: tests that mutate
	// app's openVaultHandleFn / appCanonicalProjectRootFn / resolveBindingViewAppFn
	// flow through these closures because they read the current value at
	// call time. Same pattern as the auditlog seams above. hasp-da2w.
	vaultaccess.OpenVaultFn = func(ctx context.Context) (*store.Handle, error) {
		return openVaultHandleFn(ctx)
	}
	vaultaccess.CanonicalProjectRootFn = func(ctx context.Context, projectPath string) (string, error) {
		return appCanonicalProjectRootFn(ctx, projectPath)
	}
	vaultaccess.ResolveBindingViewFn = func(handle *store.Handle, ctx context.Context, projectPath string) (store.Binding, []store.VisibleReference, error) {
		return resolveBindingViewAppFn(handle, ctx, projectPath)
	}

	// Closure-indirection registration for cmddispatch (hasp-0u3n).
	// Production callers in app keep using the package-private helpers
	// directly; secretops (and future subpackages) consume the wrappers.
	cmddispatch.PrintHelpTopicFn = printHelpTopic
	cmddispatch.IsHelpArgFn = isHelpArg
	cmddispatch.WriteJSONResponseFn = writeJSONResponse
	cmddispatch.RenderJSONOrHumanFn = renderJSONOrHuman
	cmddispatch.JSONFlagFn = func(ctx context.Context) bool { return globalFlagsFromContext(ctx).json }
	cmddispatch.YesFlagFn = func(ctx context.Context) bool { return globalFlagsFromContext(ctx).yes }
}

func setAuditHMACKey(key []byte) { auditlog.SetHMACKey(key) }
func getAuditHMACKey() []byte    { return auditlog.GetHMACKey() }
func clearAuditHMACKey()         { auditlog.ClearHMACKey() }
var newVaultStoreFn = func() (*store.Store, error) {
	return store.New(store.NewDefaultKeyring())
}
var openStoreWithPasswordFn = func(ctx context.Context, vaultStore *store.Store, password string) (*store.Handle, error) {
	return vaultStore.OpenWithPassword(ctx, password)
}
var ensureSessionAppFn = brokerops.EnsureSession
var resolveBindingViewFn = (*store.Handle).ResolveBindingView
var getItemAppFn = (*store.Handle).GetItem
var authorizeCaptureFn = brokerops.AuthorizeCapture

func initCommand(ctx context.Context, stdout io.Writer) error {
	return initCommandWithArgs(ctx, nil, stdout)
}

func initCommandWithArgs(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp init [--json]")
	}
	vaultStore, err := newVaultStoreFn()
	if err != nil {
		return err
	}
	password, err := loadMasterPassword()
	if err != nil {
		return err
	}
	if err := vaultStore.Init(ctx, password); err != nil {
		return err
	}
	// Derive the audit HMAC key from the freshly-initialised vault so the
	// EventInit line below is signed under the same key as every event
	// that follows. Without this, the very first audit event would be
	// stamped with the legacy SHA-256 scheme and Verify under the
	// post-init key would (correctly) report a mixed chain that confuses
	// operators staring at "audit verify" for the first time.
	if handle, oerr := openStoreWithPasswordFn(ctx, vaultStore, password); oerr == nil && handle != nil {
		setAuditHMACKey(handle.AuditHMACKey())
	}
	appendAudit(audit.EventInit, "user", map[string]any{"version": runtime.VersionString()})
	payload := map[string]any{"status": "initialized"}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSimpleAction(ctx, w, "Vault initialized", "Initialized the local encrypted vault.",
			cliPair("Status", "initialized"),
		)
	})
}

func importCommand(ctx context.Context, args []string, stdout io.Writer) error {
	return importCommandWithInput(ctx, args, nil, stdout)
}

func importCommandWithInput(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", "", "")
	bind := fs.Bool("bind", false, "")
	name := fs.String("name", "", "")
	previewOnly := fs.Bool("preview", false, "")
	format := fs.String("format", "auto", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hasp import [--project-root <path>] [--bind] [--name <name>] [--preview] [--format auto|env|json] <path|->")
	}
	if expandedRoot, expandErr := expandUserPath(strings.TrimSpace(*projectRoot)); expandErr != nil {
		return fmt.Errorf("--project-root: %w", expandErr)
	} else {
		*projectRoot = expandedRoot
	}

	aliasContext := map[string]string{}
	if *bind && strings.TrimSpace(*projectRoot) != "" {
		if existing, _, _, err := bootstrapAliasContext(ctx, *projectRoot, defaultBootstrapDeps()); err == nil {
			aliasContext = existing
		}
	}
	prepared, err := prepareImport(fs.Arg(0), *format, *name, stdin, *bind, aliasContext)
	if err != nil {
		return err
	}
	defer prepared.Cleanup()
	if *previewOnly {
		return encodeImportCommandResultWithMode(ctx, stdout, prepared.Preview, nil, false, *jsonOutput)
	}

	vaultStore, err := newVaultStoreFn()
	if err != nil {
		return err
	}
	password, err := loadMasterPassword()
	if err != nil {
		return err
	}
	handle, err := openStoreWithPasswordFn(ctx, vaultStore, password)
	if err != nil {
		return err
	}
	result, err := handle.ImportPath(ctx, prepared.Path, store.ImportOptions{
		ProjectRoot:   *projectRoot,
		BindToProject: *bind,
		Name:          *name,
	})
	if err != nil {
		return err
	}
	appendAudit(audit.EventImport, "user", map[string]any{"path": fs.Arg(0), "count": len(result.Imported)})
	return encodeImportCommandResultWithMode(ctx, stdout, prepared.Preview, &result, true, *jsonOutput)
}

func setCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	emitDeprecationWarning(ctx, stderr, "[hasp] 'hasp set' is deprecated; use 'hasp secret add --vault-only' (with --from-stdin for non-interactive scripts).\n")
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	name := fs.String("name", "", "")
	kind := fs.String("kind", string(store.ItemKindKV), "")
	value := fs.String("value", "", "")
	valueStdin := fs.Bool("value-stdin", false, "")
	fromFile := fs.String("from-file", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("usage: hasp set --name <name> [--kind kv|file] [--value <value> | --value-stdin | --from-file <path>]")
	}
	if *value != "" && *valueStdin {
		return errors.New("--value and --value-stdin are mutually exclusive")
	}
	if *fromFile != "" {
		expandedFile, expandErr := expandUserPath(strings.TrimSpace(*fromFile))
		if expandErr != nil {
			return fmt.Errorf("--from-file: %w", expandErr)
		}
		*fromFile = expandedFile
	}
	vaultStore, err := newVaultStoreFn()
	if err != nil {
		return err
	}
	password, err := loadMasterPassword()
	if err != nil {
		return err
	}
	handle, err := openStoreWithPasswordFn(ctx, vaultStore, password)
	if err != nil {
		return err
	}
	var payload []byte
	switch {
	case *valueStdin:
		raw, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		trimmed := strings.TrimRight(string(raw), "\r\n")
		if trimmed == "" {
			return errors.New("empty value: --value-stdin requires a non-empty value on stdin")
		}
		payload = []byte(trimmed)
	case *value != "":
		_, _ = fmt.Fprintf(stderr, "WARNING: --value puts the secret on argv (visible in ps, shell history); prefer --value-stdin\n")
		appendAudit("secret.set.argv_plaintext", "user", map[string]any{
			"action":      "secret.set.argv_plaintext",
			"surface":     "cli",
			"actor_label": secretActorLabel(),
			"item_name":   *name,
			"category":    "warn",
		})
		var err error
		payload, err = resolveValue(*value, *fromFile)
		if err != nil {
			return err
		}
	default:
		var err error
		payload, err = resolveValue(*value, *fromFile)
		if err != nil {
			return err
		}
	}
	item, err := handle.UpsertItem(*name, store.ItemKind(*kind), payload, store.ItemMetadata{})
	if err != nil {
		return err
	}
	appendAudit(audit.EventCapture, "user", map[string]any{"item_name": item.Name, "kind": item.Kind})
	resultPayload := map[string]any{"item_name": item.Name, "kind": item.Kind}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, resultPayload, func(w io.Writer) error {
		return renderSimpleAction(ctx, w, "Secret saved", "Saved the secret into the vault.",
			cliPair("Name", item.Name),
			cliPair("Kind", string(item.Kind)),
		)
	})
}

func captureCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	name := fs.String("name", "", "")
	kind := fs.String("kind", string(store.ItemKindKV), "")
	value := fs.String("value", "", "")
	fromFile := fs.String("from-file", "", "")
	projectRoot := fs.String("project-root", ".", "")
	sessionToken := fs.String("session-token", "", "")
	bind := fs.Bool("bind", false, "")
	projectGrant := fs.String("grant-project", "", "")
	secretGrant := fs.String("grant-secret", "", "")
	window := fs.Duration("grant-window", 0, "")
	grantWrite := fs.Bool("grant-write", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("usage: hasp capture --name <name> [--kind kv|file] [--value <value> | --from-file <path>] [--project-root <path>] [--bind] [--session-token <token>] [--grant-project once|session|window|<duration>] [--grant-secret once|session|window|<duration>] [--grant-window 15m] [--grant-write]")
	}
	projScope, projTTL, err := resolveGrant(*projectGrant, *window)
	if err != nil {
		return err
	}
	secScope, secTTL, err := resolveGrant(*secretGrant, *window)
	if err != nil {
		return err
	}
	effectiveWindow, err := pickGrantWindow(projTTL, secTTL, *window)
	if err != nil {
		return err
	}
	if err := validateGrantWindow(string(projScope), string(secScope), "", effectiveWindow); err != nil {
		return err
	}
	session, err := ensureSessionAppFn(ctx, s, *projectRoot, *sessionToken, "human-cli")
	if err != nil {
		return err
	}
	vaultStore, err := newVaultStoreFn()
	if err != nil {
		return err
	}
	password, err := loadMasterPassword()
	if err != nil {
		return err
	}
	handle, err := openStoreWithPasswordFn(ctx, vaultStore, password)
	if err != nil {
		return err
	}
	payload, err := resolveValue(*value, *fromFile)
	if err != nil {
		return err
	}
	binding, _, _, err := ensureProjectBinding(ctx, handle, *projectRoot)
	if err != nil {
		return err
	}
	if err := requireProjectBinding(binding, *projectRoot); err != nil {
		return err
	}
	_, existingErr := getItemAppFn(handle, *name)
	creatingNew := errors.Is(existingErr, store.ErrItemNotFound)
	if existingErr != nil && !creatingNew {
		return existingErr
	}
	if err := authorizeCaptureFn(
		ctx,
		handle,
		binding.ID,
		session.Token,
		*name,
		projScope,
		secScope,
		effectiveWindow,
		*grantWrite,
	); err != nil {
		return err
	}
	if creatingNew && *grantWrite {
		appendAudit(audit.EventApprove, "user", map[string]any{"action": "capture.write_grant", "binding_id": binding.ID, "item_name": *name})
	}
	result, err := handle.Capture(ctx, *projectRoot, *name, store.ItemKind(*kind), payload, *bind)
	if err != nil {
		return err
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, result, func(w io.Writer) error {
		return renderSimpleAction(ctx, w, "Secret captured", "Stored the value in the vault.",
			cliPair("Name", result.ItemName),
			cliPair("Kind", string(result.ItemKind)),
			cliPair("Reference", result.Reference),
			cliPair("Alias", result.Alias),
		)
	})
}

func redactCommand(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	vaultStore, err := newVaultStoreFn()
	if err != nil {
		return err
	}
	password, err := loadMasterPassword()
	if err != nil {
		return err
	}
	handle, err := openStoreWithPasswordFn(ctx, vaultStore, password)
	if err != nil {
		return err
	}
	input, err := io.ReadAll(stdin)
	if err != nil {
		return err
	}
	result := redactor.Apply(input, handle.ListItems())
	_, err = stdout.Write(result.Output)
	return err
}

func auditCommand(ctx context.Context, stdout io.Writer) error {
	return auditCommandWithArgs(ctx, nil, stdout)
}

func auditCommandWithArgs(ctx context.Context, args []string, stdout io.Writer) error {
	// `hasp audit tail` is a streaming sub-subcommand with its own flag
	// surface; route before the general `audit` parser so flags like `-n`
	// and `-f` don't collide with the verify/incident parsing below.
	if len(args) > 0 && args[0] == "tail" {
		return auditTailCommand(ctx, args[1:], stdout, defaultAuditTailOpts())
	}
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	incidentBundle := fs.Bool("incident-bundle", false, "")
	filterSecret := fs.String("secret", "", "")
	filterProjectRoot := fs.String("project-root", "", "")
	filterAgent := fs.String("agent", "", "")
	filterAction := fs.String("action", "", "")
	filterBlocked := fs.Bool("blocked", false, "")
	filterSince := fs.String("since", "", "")
	var verifyMode bool
	fs.BoolVar(&verifyMode, "verify", false, "verify the audit chain HMAC and exit")
	var format string
	fs.StringVar(&format, "format", "", "output format: timeline, table, or json")
	// Allow `hasp audit verify [flags]` as a subcommand alias for
	// `hasp audit --verify [flags]`. flag.Parse stops at the first
	// non-flag, so we strip a leading "verify" before parsing instead
	// of inspecting the trailing positionals after parsing — that lets
	// flags placed after the alias (e.g. `audit verify --json`) parse
	// normally.
	verifyAlias := false
	if len(args) > 0 && args[0] == "verify" {
		verifyAlias = true
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if verifyAlias {
		verifyMode = true
	}
	if tail := fs.Args(); len(tail) != 0 {
		return errors.New("usage: hasp audit [verify] [--json] [--incident-bundle]")
	}
	if expandedRoot, expandErr := expandUserPath(strings.TrimSpace(*filterProjectRoot)); expandErr != nil {
		return fmt.Errorf("--project-root: %w", expandErr)
	} else {
		*filterProjectRoot = expandedRoot
	}

	// Resolve --blocked: only treat as active if the flag was explicitly set.
	var blockedPtr *bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "blocked" {
			v := *filterBlocked
			blockedPtr = &v
		}
	})

	// Resolve --since: accept RFC3339 timestamp or Go duration.
	var sinceTime time.Time
	if *filterSince != "" {
		if d, err := time.ParseDuration(*filterSince); err == nil {
			sinceTime = time.Now().UTC().Add(-d)
		} else if t, err := time.Parse(time.RFC3339, *filterSince); err == nil {
			sinceTime = t
		} else {
			return errors.New("--since: value must be an RFC3339 timestamp or a Go duration (e.g. 1h)")
		}
	}

	filterOpts := auditFilterOptions{
		Secret:      *filterSecret,
		ProjectRoot: *filterProjectRoot,
		Agent:       *filterAgent,
		Action:      *filterAction,
		Blocked:     blockedPtr,
		Since:       sinceTime,
	}
	hasFilters := filterOpts.Secret != "" || filterOpts.ProjectRoot != "" ||
		filterOpts.Agent != "" || filterOpts.Action != "" ||
		filterOpts.Blocked != nil || !filterOpts.Since.IsZero()

	log, err := newAuditLogFn()
	if err != nil {
		return err
	}
	// Install the HMAC key best-effort: if the vault is unlocked we can
	// verify HMAC-stamped events; if not, we skip the install and Verify
	// surfaces a clear "hmac key not installed" error on any keyed line
	// instead of silently passing the chain.
	if log != nil {
		if key := getAuditHMACKey(); len(key) > 0 {
			log = log.WithKey(key)
		} else if handle, oerr := openVaultHandleFn(ctx); oerr == nil && handle != nil {
			log = log.WithKey(handle.AuditHMACKey())
		}
		if err := log.Verify(); err != nil {
			return err
		}
	}
	if verifyMode {
		payload := map[string]any{"status": "ok", "chain": "verified"}
		return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
			return renderSimpleAction(ctx, w, "Audit verified", "The local audit chain authenticates under the current vault key.",
				cliPair("Status", "ok"),
			)
		})
	}

	// Dispatch to human-readable renderers when --format=timeline or --format=table.
	if format == "timeline" || format == "table" {
		events, err := auditEventsFn(log)
		if err != nil {
			return err
		}
		if hasFilters {
			events = auditFilterEvents(events, filterOpts)
		}
		if format == "timeline" {
			return auditRenderTimeline(events, stdout)
		}
		return auditRenderTable(events, stdout)
	}

	if *incidentBundle || hasFilters {
		events, err := auditEventsFn(log)
		if err != nil {
			return err
		}
		if hasFilters {
			events = auditFilterEvents(events, filterOpts)
		}
		redacted := make([]audit.Event, 0, len(events))
		for _, event := range events {
			redacted = append(redacted, redactAuditEvent(event))
		}
		payload := map[string]any{"status": "ok", "events": redacted}
		return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
			return renderSimpleAction(ctx, w, "Incident bundle", "Exported redacted time-ordered audit evidence.",
				cliPair("Events", strconv.Itoa(len(redacted))),
				cliPair("Status", "ok"),
			)
		})
	}
	payload := map[string]any{"status": "ok"}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSimpleAction(ctx, w, "Audit verified", "Verified the local audit log chain.",
			cliPair("Status", "ok"),
		)
	})
}

func redactAuditEvent(event audit.Event) audit.Event {
	if event.Details == nil {
		return event
	}
	event.Details = redactDetailsForHuman(event.Details)
	return event
}

func loadMasterPassword() (string, error) {
	password := os.Getenv("HASP_MASTER_PASSWORD")
	if password == "" {
		return "", errors.New("HASP_MASTER_PASSWORD is required for this command")
	}
	return password, nil
}

func resolveValue(inline string, fromFile string) ([]byte, error) {
	if inline != "" && fromFile != "" {
		return nil, errors.New("choose either --value or --from-file")
	}
	if fromFile != "" {
		return os.ReadFile(fromFile)
	}
	return []byte(inline), nil
}

func appendAudit(eventType string, actor string, details map[string]any) {
	auditlog.Append(eventType, actor, details)
}
