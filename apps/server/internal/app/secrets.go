package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/redactor"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var newAuditLogFn = audit.New
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
	appendAudit(audit.EventInit, "user", map[string]any{"version": runtime.Version()})
	_, err = fmt.Fprintln(stdout, "initialized")
	return err
}

func importCommand(ctx context.Context, args []string, stdout io.Writer) error {
	return importCommandWithInput(ctx, args, nil, stdout)
}

func importCommandWithInput(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
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

	aliasContext := map[string]string{}
	if *bind && strings.TrimSpace(*projectRoot) != "" {
		if existing, _, _, err := bootstrapAliasContext(ctx, *projectRoot); err == nil {
			aliasContext = existing
		}
	}
	prepared, err := prepareImport(fs.Arg(0), *format, *name, stdin, *bind, aliasContext)
	if err != nil {
		return err
	}
	defer prepared.Cleanup()
	if *previewOnly {
		return encodeImportCommandResult(stdout, prepared.Preview, nil, false)
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
	return encodeImportCommandResult(stdout, prepared.Preview, &result, true)
}

func setCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	name := fs.String("name", "", "")
	kind := fs.String("kind", string(store.ItemKindKV), "")
	value := fs.String("value", "", "")
	fromFile := fs.String("from-file", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("usage: hasp set --name <name> [--kind kv|file] [--value <value> | --from-file <path>]")
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
	item, err := handle.UpsertItem(*name, store.ItemKind(*kind), payload, store.ItemMetadata{})
	if err != nil {
		return err
	}
	appendAudit(audit.EventCapture, "user", map[string]any{"item_name": item.Name, "kind": item.Kind})
	return json.NewEncoder(stdout).Encode(map[string]any{"item_name": item.Name, "kind": item.Kind})
}

func captureCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	name := fs.String("name", "", "")
	kind := fs.String("kind", string(store.ItemKindKV), "")
	value := fs.String("value", "", "")
	fromFile := fs.String("from-file", "", "")
	projectRoot := fs.String("project-root", ".", "")
	sessionToken := fs.String("session-token", "", "")
	bind := fs.Bool("bind", false, "")
	projectGrant := fs.String("grant-project", "", "")
	secretGrant := fs.String("grant-secret", "", "")
	window := fs.Duration("grant-window", 15*time.Minute, "")
	grantWrite := fs.Bool("grant-write", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("usage: hasp capture --name <name> [--kind kv|file] [--value <value> | --from-file <path>] [--project-root <path>] [--bind] [--session-token <token>] [--grant-project once|session|window] [--grant-secret once|session|window] [--grant-window 15m] [--grant-write]")
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
		parseGrantScope(*projectGrant),
		parseGrantScope(*secretGrant),
		*window,
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
	return json.NewEncoder(stdout).Encode(result)
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

func auditCommand(stdout io.Writer) error {
	log, err := newAuditLogFn()
	if err != nil {
		return err
	}
	if err := log.Verify(); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "ok")
	return err
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
	log, err := newAuditLogFn()
	if err != nil {
		return
	}
	_, _ = log.Append(eventType, actor, details)
}
