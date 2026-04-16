package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/redactor"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var authorizeReferenceAppFn = brokerops.AuthorizeReference
var authorizeItemAppFn = brokerops.AuthorizeItem
var runnerExecuteFn = runner.Execute
var resolveBindingViewExecFn = (*store.Handle).ResolveBindingView
var resolveReferenceExecFn = (*store.Handle).ResolveReference
var getItemExecFn = (*store.Handle).GetItem
var grantProjectLeaseAppFn = (*store.Handle).GrantProjectLease
var grantConvenienceAppFn = (*store.Handle).GrantConvenience
var walkProjectDirFn = filepath.WalkDir
var absPathExecFn = filepath.Abs
var evalSymlinksExecFn = filepath.EvalSymlinks

type writeEnvFile interface {
	WriteString(string) (int, error)
	Close() error
}

var openWriteEnvFileFn = func(path string, flag int, perm os.FileMode) (writeEnvFile, error) {
	return os.OpenFile(path, flag, perm)
}

type mappingFlag map[string]string

func (m *mappingFlag) String() string {
	if m == nil {
		return ""
	}
	values := make([]string, 0, len(*m))
	for key, value := range *m {
		values = append(values, key+"="+value)
	}
	return strings.Join(values, ",")
}

func (m *mappingFlag) Set(value string) error {
	key, ref, ok := strings.Cut(value, "=")
	if !ok || strings.TrimSpace(key) == "" || strings.TrimSpace(ref) == "" {
		return fmt.Errorf("expected NAME=REFERENCE")
	}
	if *m == nil {
		*m = map[string]string{}
	}
	(*m)[strings.TrimSpace(key)] = strings.TrimSpace(ref)
	return nil
}

func runCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, s starter) error {
	return executeCommand(ctx, args, stdout, stderr, false, s)
}

func injectCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, s starter) error {
	return executeCommand(ctx, args, stdout, stderr, true, s)
}

func executeCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, injectOnly bool, s starter) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectRoot := fs.String("project-root", ".", "")
	sessionToken := fs.String("session-token", "", "")
	projectGrant := fs.String("grant-project", "", "")
	secretGrant := fs.String("grant-secret", "", "")
	window := fs.Duration("grant-window", 15*time.Minute, "")
	var envRefs mappingFlag
	var fileRefs mappingFlag
	fs.Var(&envRefs, "env", "")
	fs.Var(&fileRefs, "file", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	command := fs.Args()
	if len(command) == 0 {
		return errors.New("usage: hasp run --project-root <path> [--session-token <token>] [--env NAME=REF] [--file NAME=REF] [--grant-project once|session|window] [--grant-secret once|session|window] [--grant-window 15m] -- <command>")
	}
	if injectOnly && len(fileRefs) == 0 {
		return errors.New("inject requires at least one --file NAME=REFERENCE mapping")
	}
	session, err := ensureSessionAppFn(ctx, s, *projectRoot, *sessionToken, "human-cli")
	if err != nil {
		return err
	}

	handle, err := openVaultHandleFn(ctx)
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
	items := make([]store.Item, 0, len(envRefs)+len(fileRefs))
	env := map[string]string{}
	files := map[string][]byte{}
	for envName, reference := range envRefs {
		item, err := authorizeReferenceAppFn(ctx, handle, binding.ID, *projectRoot, session.Token, reference, store.OperationRun, parseGrantScope(*projectGrant), parseGrantScope(*secretGrant), store.GrantScope(""), *window, "")
		if err != nil {
			return err
		}
		env[envName] = string(item.Value)
		items = append(items, item)
	}
	for envName, reference := range fileRefs {
		item, err := authorizeReferenceAppFn(ctx, handle, binding.ID, *projectRoot, session.Token, reference, store.OperationInject, parseGrantScope(*projectGrant), parseGrantScope(*secretGrant), store.GrantScope(""), *window, "")
		if err != nil {
			return err
		}
		files[envName] = item.Value
		items = append(items, item)
	}

	result, err := runnerExecuteFn(ctx, runner.Input{
		ProjectRoot: *projectRoot,
		Command:     command,
		Env:         env,
		Files:       files,
	})
	if err != nil {
		return err
	}
	stdoutResult := redactor.Apply(result.Stdout, items)
	stderrResult := redactor.Apply(result.Stderr, items)
	if len(stdoutResult.Output) > 0 {
		if _, err := stdout.Write(stdoutResult.Output); err != nil {
			return err
		}
	}
	if len(stderrResult.Output) > 0 {
		if _, err := stderr.Write(stderrResult.Output); err != nil {
			return err
		}
	}
	if stdoutResult.Redacted || stderrResult.Redacted || stdoutResult.Suppressed || stderrResult.Suppressed {
		appendAudit(audit.EventRedact, "user", map[string]any{
			"project_root": *projectRoot,
			"redacted":     stdoutResult.Redacted || stderrResult.Redacted,
			"suppressed":   stdoutResult.Suppressed || stderrResult.Suppressed,
		})
	}
	appendAudit(audit.EventRun, "user", map[string]any{"project_root": *projectRoot, "exit_code": result.ExitCode, "args": command})
	if result.ExitCode != 0 {
		return fmt.Errorf("command exited with code %d", result.ExitCode)
	}
	return nil
}

func writeEnvCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, s starter) error {
	fs := flag.NewFlagSet("write-env", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectRoot := fs.String("project-root", ".", "")
	sessionToken := fs.String("session-token", "", "")
	outputPath := fs.String("output", "", "")
	appendMode := fs.Bool("append", false, "")
	projectGrant := fs.String("grant-project", "", "")
	secretGrant := fs.String("grant-secret", "", "")
	convenienceGrant := fs.String("grant-convenience", "", "")
	window := fs.Duration("grant-window", 15*time.Minute, "")
	var envRefs mappingFlag
	fs.Var(&envRefs, "env", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *outputPath == "" || len(envRefs) == 0 {
		return errors.New("usage: hasp write-env --project-root <path> [--session-token <token>] --output <file> --env NAME=REF [--append] [--grant-project once|session|window] [--grant-secret once|session|window] [--grant-convenience once|window]")
	}
	session, err := ensureSessionAppFn(ctx, s, *projectRoot, *sessionToken, "human-cli")
	if err != nil {
		return err
	}
	handle, err := openVaultHandleFn(ctx)
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
	lines := make([]string, 0, len(envRefs))
	resolvedItems := make(map[string]store.Item, len(envRefs))
	itemSet := make([]string, 0, len(envRefs))
	for _, reference := range envRefs {
		resolved, err := resolveReferenceExecFn(handle, ctx, *projectRoot, reference)
		if err != nil {
			return err
		}
		item, err := getItemExecFn(handle, resolved.ItemName)
		if err != nil {
			return err
		}
		resolvedItems[reference] = item
		itemSet = append(itemSet, item.Name)
	}
	if len(itemSet) > 0 {
		decision := handle.Authorize(store.AccessRequest{
			Operation:       store.OperationWriteEnv,
			BindingID:       binding.ID,
			SessionToken:    session.Token,
			DestinationPath: *outputPath,
			Aliases:         itemSet,
		})
		if decision.RequiresPrompt {
			switch decision.Reason {
			case "project_and_convenience_approval_required":
				if parseGrantScope(*projectGrant) == "" {
					return errors.New("project lease required for write-env")
				}
				if _, err := grantProjectLeaseAppFn(handle, binding.ID, session.Token, parseGrantScope(*projectGrant), *window); err != nil {
					return err
				}
				fallthrough
			case "convenience_approval_required":
				if parseGrantScope(*convenienceGrant) == "" {
					return errors.New("convenience approval required for write-env")
				}
				if _, err := grantConvenienceAppFn(handle, binding.ID, session.Token, *outputPath, itemSet, "user", parseGrantScope(*convenienceGrant), *window); err != nil {
					return err
				}
			}
		}
	}
	for envName, reference := range envRefs {
		item := resolvedItems[reference]
		item, err := authorizeItemAppFn(handle, binding.ID, session.Token, item, store.OperationRun, parseGrantScope(*projectGrant), parseGrantScope(*secretGrant), *window)
		if err != nil {
			return err
		}
		lines = append(lines, envName+"="+string(item.Value))
	}
	flags := os.O_CREATE | os.O_WRONLY
	if *appendMode {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	file, err := openWriteEnvFileFn(*outputPath, flags, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return err
	}
	warning := ""
	root, err := store.CanonicalProjectRoot(ctx, *projectRoot)
	if err == nil && pathInsideProject(*outputPath, root) {
		warning = "destination is inside the bound project and outside the agent-safe guarantee"
		_, _ = fmt.Fprintln(stderr, warning)
	}
	appendAudit(audit.EventWriteEnv, "user", map[string]any{"project_root": *projectRoot, "output_path": *outputPath, "entries": len(lines), "warning": warning})
	return json.NewEncoder(stdout).Encode(map[string]any{"output_path": *outputPath, "entries": len(lines), "warning": warning})
}

func checkRepoCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("check-repo", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectRoot := fs.String("project-root", ".", "")
	allowManagedSecrets := fs.Bool("allow-managed-secrets", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	root, err := appCanonicalProjectRootFn(ctx, *projectRoot)
	if err != nil {
		return err
	}
	var matches []map[string]string
	items := handle.ListItems()
	err = walkProjectDirFn(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, item := range items {
			if len(item.Value) == 0 {
				continue
			}
			if strings.Contains(string(data), string(item.Value)) {
				matches = append(matches, map[string]string{"path": path, "item_name": item.Name})
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(matches) > 0 {
		appendAudit(audit.EventRepoBlock, "user", map[string]any{"project_root": root, "matches": len(matches), "override": *allowManagedSecrets})
		_ = json.NewEncoder(stdout).Encode(map[string]any{"matches": matches, "override": *allowManagedSecrets})
		if *allowManagedSecrets {
			return nil
		}
		return errors.New("managed secrets detected in repository files")
	}
	return json.NewEncoder(stdout).Encode(map[string]any{"matches": matches, "override": *allowManagedSecrets})
}

func parseGrantScope(value string) store.GrantScope {
	switch strings.TrimSpace(value) {
	case string(store.GrantOnce):
		return store.GrantOnce
	case string(store.GrantSession):
		return store.GrantSession
	case string(store.GrantWindow):
		return store.GrantWindow
	default:
		return ""
	}
}

func pathInsideProject(path string, root string) bool {
	if root == "" {
		return false
	}
	absPath, err1 := absPathExecFn(path)
	absRoot, err2 := absPathExecFn(root)
	if err1 != nil || err2 != nil {
		return false
	}
	if resolvedPath, err := evalSymlinksExecFn(absPath); err == nil {
		absPath = resolvedPath
	}
	if resolvedRoot, err := evalSymlinksExecFn(absRoot); err == nil {
		absRoot = resolvedRoot
	}
	return absPath == absRoot || strings.HasPrefix(absPath, absRoot+string(filepath.Separator))
}
