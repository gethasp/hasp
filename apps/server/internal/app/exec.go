package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/gitsafe"
	"github.com/gethasp/hasp/apps/server/internal/redactor"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// execDeps bundles every seam that the run/inject, write-env and
// check-repo commands need: broker authorisation, runner execution,
// store-handle resolution and grant issuance, plus filesystem walkers
// and path canonicalisation. Tests construct a local instance so they
// can drive a single failure branch without holding the process-wide
// app-seam mutex.
type execDeps struct {
	AuthorizeReference  func(ctx context.Context, handle *store.Handle, bindingID, projectRoot, sessionToken, reference string, op store.Operation, projScope, secScope, convScope store.GrantScope, window time.Duration, dest string) (store.Item, error)
	AuthorizeItem       func(handle *store.Handle, bindingID, sessionToken string, item store.Item, op store.Operation, projScope, secScope store.GrantScope, window time.Duration) (store.Item, error)
	RunnerExecute       func(ctx context.Context, input runner.Input) (runner.Result, error)
	ResolveBindingView  func(handle *store.Handle, ctx context.Context, projectRoot string) (store.Binding, []store.VisibleReference, error)
	ResolveReference    func(handle *store.Handle, ctx context.Context, projectRoot, reference string) (store.ResolvedReference, error)
	GetItem             func(handle *store.Handle, name string) (store.Item, error)
	GrantProjectLease   func(handle *store.Handle, bindingID, sessionToken string, scope store.GrantScope, window time.Duration) (store.ProjectLease, error)
	GrantConvenience    func(handle *store.Handle, bindingID, sessionToken, dest string, items []string, principal string, scope store.GrantScope, window time.Duration) (store.ConvenienceGrant, error)
	WalkProjectDir      func(root string, fn fs.WalkDirFunc) error
	AbsPath             func(path string) (string, error)
	EvalSymlinks        func(path string) (string, error)
	OpenWriteEnvFile    func(path string, flag int, perm os.FileMode) (writeEnvFile, error)
	GitLsFiles          func(ctx context.Context, root string) ([]string, error)
	// RunnerStdin is the io.Reader forwarded to the child process as its stdin.
	// When nil, os.Stdin is used in production and nil (no stdin) in tests.
	RunnerStdin         io.Reader
}

func defaultExecDeps() execDeps {
	return execDeps{
		AuthorizeReference: brokerops.AuthorizeReference,
		AuthorizeItem:      brokerops.AuthorizeItem,
		RunnerExecute:      runner.Execute,
		ResolveBindingView: (*store.Handle).ResolveBindingView,
		ResolveReference:   (*store.Handle).ResolveReference,
		GetItem:            (*store.Handle).GetItem,
		GrantProjectLease:  (*store.Handle).GrantProjectLease,
		GrantConvenience:   (*store.Handle).GrantConvenience,
		WalkProjectDir: filepath.WalkDir,
		AbsPath:      filepath.Abs,
		EvalSymlinks: filepath.EvalSymlinks,
		RunnerStdin:  os.Stdin,
		OpenWriteEnvFile: func(path string, flag int, perm os.FileMode) (writeEnvFile, error) {
			return os.OpenFile(path, flag, perm)
		},
		GitLsFiles: func(ctx context.Context, root string) ([]string, error) {
			cmd := gitsafe.BuildCommand(ctx, root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
			out, err := cmd.Output()
			if err != nil {
				return nil, err
			}
			parts := bytes.Split(out, []byte{0})
			files := make([]string, 0, len(parts))
			for _, p := range parts {
				trimmed := strings.TrimSpace(string(p))
				if trimmed != "" {
					files = append(files, trimmed)
				}
			}
			return files, nil
		},
	}
}

// checkRepoMaxBytes bounds each per-file scan so LFS packs, sqlite artefacts,
// or accidental multi-GB test fixtures cannot OOM the daemon. Files over the
// cap are reported under "skipped" so the operator knows they were not
// scanned. The default is 4 MiB, which comfortably covers normal source
// files while cutting off LFS pointer-replaced binaries.
var checkRepoMaxBytes int64 = 4 << 20

type writeEnvFile interface {
	WriteString(string) (int, error)
	Close() error
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
	return executeCommandWithDeps(ctx, args, stdout, stderr, false, s, defaultExecDeps())
}

func injectCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, s starter) error {
	return executeCommandWithDeps(ctx, args, stdout, stderr, true, s, defaultExecDeps())
}

func executeCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, injectOnly bool, s starter) error {
	return executeCommandWithDeps(ctx, args, stdout, stderr, injectOnly, s, defaultExecDeps())
}

func executeCommandWithDeps(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, injectOnly bool, s starter, deps execDeps) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectRoot := fs.String("project-root", ".", "")
	sessionToken := fs.String("session-token", "", "")
	projectGrant := fs.String("grant-project", "", "")
	secretGrant := fs.String("grant-secret", "", "")
	window := fs.Duration("grant-window", 0, "")
	explain := fs.Bool("explain", false, "")
	dryRun := fs.Bool("dry-run", false, "")
	explainFormat := fs.String("explain-format", "text", "")
	var envRefs mappingFlag
	var fileRefs mappingFlag
	fs.Var(&envRefs, "env", "")
	fs.Var(&fileRefs, "file", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	expandedRoot, err := expandUserPath(strings.TrimSpace(*projectRoot))
	if err != nil {
		return fmt.Errorf("--project-root: %w", err)
	}
	*projectRoot = expandedRoot
	command := fs.Args()
	if len(command) == 0 && !*dryRun {
		return errors.New("usage: hasp run --project-root <path> [--session-token <token>] [--env NAME=REF] [--file NAME=REF] [--grant-project once|session|window|<duration>] [--grant-secret once|session|window|<duration>] [--grant-window 15m] [--explain [--dry-run]] -- <command>")
	}
	if injectOnly && len(fileRefs) == 0 {
		return errors.New("inject requires at least one --file NAME=REFERENCE mapping (use hasp run for env-only delivery)")
	}
	if *dryRun && !*explain {
		*explain = true
	}
	commandLabel := "run"
	if injectOnly {
		commandLabel = "inject"
	}
	warnBareEnvRefs(ctx, stderr, envRefs, commandLabel, "--env")
	warnBareEnvRefs(ctx, stderr, fileRefs, commandLabel, "--file")
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
	if *explain {
		if err := writeExplainPayload(stderr, explainPayload{
			Command:        commandLabel,
			ProjectRoot:    *projectRoot,
			ProjectScope:   string(projScope),
			SecretScope:    string(secScope),
			GrantWindow:    effectiveWindow,
			RedactorActive: true,
			EnvRefs:        envRefs,
			FileRefs:       fileRefs,
			ChildCommand:   command,
			DryRun:         *dryRun,
		}, *explainFormat); err != nil {
			return err
		}
		if *dryRun {
			return nil
		}
	}
	if abs, absErr := filepath.Abs(*projectRoot); absErr == nil {
		noteResolvedProjectRootIfImplicit(fs, false, abs, stderr)
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
		item, err := deps.AuthorizeReference(ctx, handle, binding.ID, *projectRoot, session.Token, reference, store.OperationRun, projScope, secScope, store.GrantScope(""), effectiveWindow, "")
		if err != nil {
			return wrapAuthorizeReferenceError(err)
		}
		env[envName] = string(item.Value)
		items = append(items, item)
	}
	for envName, reference := range fileRefs {
		item, err := deps.AuthorizeReference(ctx, handle, binding.ID, *projectRoot, session.Token, reference, store.OperationInject, projScope, secScope, store.GrantScope(""), effectiveWindow, "")
		if err != nil {
			return wrapAuthorizeReferenceError(err)
		}
		files[envName] = item.Value
		items = append(items, item)
	}

	// hasp-ymuy: when the caller's stdout is an interactive terminal, ask the
	// runner for PTY allocation so the child's isatty() returns true. PTY
	// children emit ANSI escape sequences that can split secrets across
	// styles, so the stdout redactor must use the ANSI-aware variant
	// (hasp-ab5d) — without it `AKIA\x1b[1mTOKEN\x1b[0m` would bypass
	// literal-substring matching. Stderr stays buffered and does not
	// receive a PTY because PTYs merge the two streams.
	tty := stdoutIsTTYFn(stdout)
	var swOut *redactor.StreamingWriter
	if tty {
		swOut = redactor.NewStreamingWriterANSIAware(stdout, items)
	} else {
		swOut = redactor.NewStreamingWriter(stdout, items)
	}
	swErr := redactor.NewStreamingWriter(stderr, items)

	result, err := deps.RunnerExecute(ctx, runner.Input{
		ProjectRoot: *projectRoot,
		Command:     command,
		Env:         env,
		Files:       files,
		Stdin:       deps.RunnerStdin,
		Stdout:      swOut,
		Stderr:      swErr,
		TTY:         tty,
	})
	// Flush streaming writers regardless of error so buffered bytes are
	// not silently dropped.
	flushErrOut := swOut.Flush()
	flushErrErr := swErr.Flush()
	if err != nil {
		return err
	}
	if flushErrOut != nil {
		return flushErrOut
	}
	if flushErrErr != nil {
		return flushErrErr
	}

	// Collect aggregated stats from both streams.
	statsOut := swOut.Stats()
	statsErr := swErr.Stats()

	if statsOut.Redacted || statsErr.Redacted {
		appendAudit(audit.EventRedact, "user", map[string]any{
			"project_root":   *projectRoot,
			"redacted":       true,
			"suppressed":     false,
			"redacted_items": mergeRedactedItems(statsOut.MatchedItems, statsErr.MatchedItems),
		})
	}
	appendAudit(audit.EventRun, "user", map[string]any{"project_root": *projectRoot, "exit_code": result.ExitCode, "args": command})
	if result.ExitCode != 0 {
		return fmt.Errorf("command exited with code %d", result.ExitCode)
	}
	return nil
}

const (
	writeEnvBlockBegin = "# --- hasp begin ---"
	writeEnvBlockEnd   = "# --- hasp end ---"
)

func writeEnvCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, s starter) error {
	return writeEnvCommandWithDeps(ctx, args, stdout, stderr, s, defaultExecDeps())
}

func writeEnvCommandWithDeps(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, s starter, deps execDeps) error {
	fs := flag.NewFlagSet("write-env", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", ".", "")
	sessionToken := fs.String("session-token", "", "")
	outputPath := fs.String("output", "", "")
	appendMode := fs.Bool("append", false, "")
	forceMode := fs.Bool("force", false, "")
	projectGrant := fs.String("grant-project", "", "")
	secretGrant := fs.String("grant-secret", "", "")
	convenienceGrant := fs.String("grant-convenience", "", "")
	window := fs.Duration("grant-window", 0, "")
	var envRefs mappingFlag
	fs.Var(&envRefs, "env", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *outputPath == "" || len(envRefs) == 0 {
		return errors.New("usage: hasp write-env --project-root <path> [--session-token <token>] --output <file> --env NAME=REF [--append] [--force] [--grant-project once|session|window|<duration>] [--grant-secret once|session|window|<duration>] [--grant-convenience once|window|<duration>]")
	}
	expandedRoot, err := expandUserPath(strings.TrimSpace(*projectRoot))
	if err != nil {
		return fmt.Errorf("--project-root: %w", err)
	}
	*projectRoot = expandedRoot
	expandedOutput, err := expandUserPath(strings.TrimSpace(*outputPath))
	if err != nil {
		return fmt.Errorf("--output: %w", err)
	}
	*outputPath = expandedOutput
	if *forceMode && *appendMode {
		return errors.New("--force and --append are mutually exclusive")
	}
	if !*jsonOutput {
		warnBareEnvRefs(ctx, stderr, envRefs, "write-env", "--env")
	}
	projScope, projTTL, err := resolveGrant(*projectGrant, *window)
	if err != nil {
		return err
	}
	secScope, secTTL, err := resolveGrant(*secretGrant, *window)
	if err != nil {
		return err
	}
	convScope, convTTL, err := resolveGrant(*convenienceGrant, *window)
	if err != nil {
		return err
	}
	effectiveWindow, err := pickGrantWindow(projTTL, secTTL, convTTL, *window)
	if err != nil {
		return err
	}
	if err := validateGrantWindow(string(projScope), string(secScope), string(convScope), effectiveWindow); err != nil {
		return err
	}
	if abs, absErr := filepath.Abs(*projectRoot); absErr == nil {
		noteResolvedProjectRootIfImplicit(fs, *jsonOutput, abs, stderr)
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
	// Overwrite guard: when neither --force nor --append, refuse if file exists.
	if !*appendMode && !*forceMode {
		if _, statErr := os.Stat(*outputPath); statErr == nil {
			return fmt.Errorf("refusing to overwrite existing %s; pass --force to overwrite or --append to merge", *outputPath)
		}
	}

	lines := make([]string, 0, len(envRefs))
	resolvedItems := make(map[string]store.Item, len(envRefs))
	itemSet := make([]string, 0, len(envRefs))
	for _, reference := range envRefs {
		resolved, err := deps.ResolveReference(handle, ctx, *projectRoot, reference)
		if err != nil {
			return err
		}
		item, err := deps.GetItem(handle, resolved.ItemName)
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
				if projScope == "" {
					return errors.New("project lease required for write-env")
				}
				if _, err := deps.GrantProjectLease(handle, binding.ID, session.Token, projScope, effectiveWindow); err != nil {
					return err
				}
				fallthrough
			case "convenience_approval_required":
				if convScope == "" {
					return errors.New("convenience approval required for write-env")
				}
				if _, err := deps.GrantConvenience(handle, binding.ID, session.Token, *outputPath, itemSet, "user", convScope, effectiveWindow); err != nil {
					return err
				}
			}
		}
	}
	for envName, reference := range envRefs {
		item := resolvedItems[reference]
		item, err := deps.AuthorizeItem(handle, binding.ID, session.Token, item, store.OperationRun, projScope, secScope, effectiveWindow)
		if err != nil {
			return err
		}
		lines = append(lines, envName+"="+string(item.Value))
	}
	if *appendMode {
		// Block-splice append: read existing, insert/replace hasp block.
		existing, readErr := os.ReadFile(*outputPath)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}

		count := strings.Count(string(existing), writeEnvBlockBegin)
		if count > 1 {
			return fmt.Errorf("ambiguous hasp blocks in %s: found %d begin markers, refusing to rewrite", *outputPath, count)
		}

		newBlock := writeEnvBlockBegin + "\n" + strings.Join(lines, "\n") + "\n" + writeEnvBlockEnd + "\n"

		var output []byte
		if count == 0 {
			// No existing block: append after existing content.
			if len(existing) == 0 {
				output = []byte(newBlock)
			} else {
				trimmed := strings.TrimRight(string(existing), "\n")
				output = []byte(trimmed + "\n" + newBlock)
			}
		} else {
			// count == 1: splice — replace the span from begin marker to end of end-marker line.
			existingStr := string(existing)
			beginIdx := strings.Index(existingStr, writeEnvBlockBegin)
			endMarkerIdx := strings.Index(existingStr[beginIdx:], writeEnvBlockEnd)
			if endMarkerIdx == -1 {
				// Malformed: no end marker; replace from begin to end of string.
				output = []byte(existingStr[:beginIdx] + newBlock)
			} else {
				endMarkerIdx += beginIdx // absolute offset of end marker start
				// Find end of the end-marker line (include the trailing newline).
				endLineEnd := endMarkerIdx + len(writeEnvBlockEnd)
				if endLineEnd < len(existingStr) && existingStr[endLineEnd] == '\n' {
					endLineEnd++
				}
				output = []byte(existingStr[:beginIdx] + newBlock + existingStr[endLineEnd:])
			}
		}

		// Write atomically: tmp file then rename.
		tmpPath := *outputPath + ".tmp"
		if err := os.WriteFile(tmpPath, output, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmpPath, *outputPath); err != nil {
			return err
		}
	} else {
		// Non-append mode (new file or --force overwrite): truncate and write.
		file, err := deps.OpenWriteEnvFile(*outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
			return err
		}
	}
	warning := ""
	root, err := store.CanonicalProjectRoot(ctx, *projectRoot)
	if err == nil && pathInsideProject(*outputPath, root) {
		warning = "destination is inside the bound project and outside the agent-safe guarantee"
		_, _ = fmt.Fprintln(stderr, warning)
	}
	appendAudit(audit.EventWriteEnv, "user", map[string]any{"project_root": *projectRoot, "output_path": *outputPath, "entries": len(lines), "warning": warning})
	payload := map[string]any{"output_path": *outputPath, "entries": len(lines), "warning": warning}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderWriteEnvResult(w, *outputPath, len(lines), warning)
	})
}

func checkRepoCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	return checkRepoCommandWithDeps(ctx, args, stdout, stderr, defaultExecDeps())
}

func checkRepoCommandWithDeps(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, deps execDeps) error {
	fs := flag.NewFlagSet("check-repo", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", ".", "")
	allowManagedSecrets := fs.Bool("allow-managed-secrets", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	expandedRoot, err := expandUserPath(strings.TrimSpace(*projectRoot))
	if err != nil {
		return fmt.Errorf("--project-root: %w", err)
	}
	*projectRoot = expandedRoot
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	root, err := appCanonicalProjectRootFn(ctx, *projectRoot)
	if err != nil {
		return err
	}
	noteResolvedProjectRootIfImplicit(fs, *jsonOutput, root, stderr)
	items := handle.ListItems()
	files, fallback, err := enumerateCheckRepoFiles(ctx, root, deps)
	if err != nil {
		return err
	}
	var matches []map[string]string
	var skipped []map[string]any
	for _, rel := range files {
		abs := filepath.Join(root, rel)
		info, statErr := os.Stat(abs)
		if statErr != nil {
			return statErr
		}
		if info.IsDir() {
			continue
		}
		if info.Size() > checkRepoMaxBytes {
			skipped = append(skipped, map[string]any{"path": rel, "size": info.Size(), "reason": "over_max_bytes"})
			continue
		}
		data, readErr := os.ReadFile(abs)
		if readErr != nil {
			return readErr
		}
		for _, item := range items {
			if hitCheckRepoItem(data, item) {
				matches = append(matches, map[string]string{"path": rel, "item_name": item.Name})
			}
		}
	}
	payload := map[string]any{
		"matches":  matches,
		"override": *allowManagedSecrets,
		"skipped":  skipped,
		"walker":   walkerLabel(fallback),
	}
	if len(matches) > 0 {
		appendAudit(audit.EventRepoBlock, "user", map[string]any{"project_root": root, "matches": len(matches), "override": *allowManagedSecrets})
		_ = renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
			return renderRepoCheckResult(w, root, matches, *allowManagedSecrets)
		})
		if *allowManagedSecrets {
			return nil
		}
		return newAppError(errCodeRepoLeak, "managed secrets detected in repository files").
			withHint("re-run with --allow-managed-secrets if the override is intentional")
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderRepoCheckResult(w, root, matches, *allowManagedSecrets)
	})
}

func walkerLabel(fallback bool) string {
	if fallback {
		return "walkdir"
	}
	return "git-ls-files"
}

// hitCheckRepoItem tests every encoded form of item.Value against data. We
// reuse redactor.Needles so the matcher catalogue stays in one place; a new
// encoding added there automatically flows into check-repo.
func hitCheckRepoItem(data []byte, item store.Item) bool {
	for _, needle := range redactor.Needles(item.Value) {
		if bytesIndex(data, needle) >= 0 {
			return true
		}
	}
	return false
}

// bytesIndex is a seam over bytes.Index so future refactors (e.g. swapping
// in a Boyer-Moore implementation) don't have to touch the scanner loop.
var bytesIndex = bytes.Index

// enumerateCheckRepoFiles prefers `git ls-files -z --exclude-standard`, which
// respects .gitignore and .git/info/exclude and skips submodule contents. If
// the project is not a git checkout, or git refuses, we fall back to
// filepath.WalkDir with a .git prune. The bool return is true when the
// WalkDir fallback was used — the JSON payload advertises which walker ran
// so callers can surface the "not a git repo, scan was non-authoritative"
// caveat in docs/CI.
func enumerateCheckRepoFiles(ctx context.Context, root string, deps execDeps) ([]string, bool, error) {
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		files, gitErr := deps.GitLsFiles(ctx, root)
		if gitErr == nil {
			return files, false, nil
		}
	}
	var files []string
	err := deps.WalkProjectDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, true, err
	}
	return files, true, nil
}

// mergeRedactedItems unions the per-stream MatchedItems lists from a stdout
// and stderr redaction pass. Returns a sorted, deduplicated slice that can
// be safely serialized into the audit event — names only, never values.
func mergeRedactedItems(stdoutItems, stderrItems []string) []string {
	seen := make(map[string]struct{}, len(stdoutItems)+len(stderrItems))
	for _, name := range stdoutItems {
		seen[name] = struct{}{}
	}
	for _, name := range stderrItems {
		seen[name] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
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
	return pathInsideProjectWithDeps(path, root, defaultExecDeps())
}

func pathInsideProjectWithDeps(path string, root string, deps execDeps) bool {
	if root == "" {
		return false
	}
	absPath, err1 := deps.AbsPath(path)
	absRoot, err2 := deps.AbsPath(root)
	if err1 != nil || err2 != nil {
		return false
	}
	if resolvedPath, err := deps.EvalSymlinks(absPath); err == nil {
		absPath = resolvedPath
	}
	if resolvedRoot, err := deps.EvalSymlinks(absRoot); err == nil {
		absRoot = resolvedRoot
	}
	return absPath == absRoot || strings.HasPrefix(absPath, absRoot+string(filepath.Separator))
}

// wrapAuthorizeReferenceError converts known broker errors into appError
// envelopes with actionable hints. Plain errors that don't match are
// returned unchanged so callers further up the stack can still inspect them.
func wrapAuthorizeReferenceError(err error) error {
	if errors.Is(err, store.ErrReferenceNotFound) {
		return newAppError(errCodeUserInput, err.Error()).
			withHint("run `hasp secret expose --project-root . <NAME>` to expose an existing secret, or `hasp secret add <NAME>` to create a new one")
	}
	if strings.Contains(err.Error(), "project lease required for run") {
		return newAppError(errCodeGrantDenied, err.Error()).
			withHint("run `hasp project bind --project-root <dir>` to bind the project, or `hasp session grant --project <id>` to grant a project lease")
	}
	return err
}
