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
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/gitsafe"
	"github.com/gethasp/hasp/apps/server/internal/redactor"
	"github.com/gethasp/hasp/apps/server/internal/reposcan"
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
	AuthorizeReference func(ctx context.Context, handle *store.Handle, bindingID, projectRoot, sessionToken, reference string, op store.Operation, projScope, secScope, convScope store.GrantScope, window time.Duration, dest string) (store.Item, error)
	AuthorizeItem      func(handle *store.Handle, bindingID, sessionToken string, item store.Item, op store.Operation, projScope, secScope store.GrantScope, window time.Duration) (store.Item, error)
	RunnerExecute      func(ctx context.Context, input runner.Input) (runner.Result, error)
	ResolveBindingView func(handle *store.Handle, ctx context.Context, projectRoot string) (store.Binding, []store.VisibleReference, error)
	ResolveReference   func(handle *store.Handle, ctx context.Context, projectRoot, reference string) (store.ResolvedReference, error)
	GetItem            func(handle *store.Handle, name string) (store.Item, error)
	GrantProjectLease  func(handle *store.Handle, bindingID, sessionToken string, scope store.GrantScope, window time.Duration) (store.ProjectLease, error)
	GrantConvenience   func(handle *store.Handle, bindingID, sessionToken, dest string, items []string, principal string, scope store.GrantScope, window time.Duration) (store.ConvenienceGrant, error)
	WalkProjectDir     func(root string, fn fs.WalkDirFunc) error
	AbsPath            func(path string) (string, error)
	EvalSymlinks       func(path string) (string, error)
	OpenWriteEnvFile   func(path string, flag int, perm os.FileMode) (writeEnvFile, error)
	GitLsFiles         func(ctx context.Context, root string) ([]string, error)
	// RunnerStdin is the io.Reader forwarded to the child process as its stdin.
	// When nil, os.Stdin is used in production and nil (no stdin) in tests.
	RunnerStdin io.Reader
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
		WalkProjectDir:     filepath.WalkDir,
		AbsPath:            filepath.Abs,
		EvalSymlinks:       filepath.EvalSymlinks,
		RunnerStdin:        os.Stdin,
		OpenWriteEnvFile:   openWriteEnvFile,
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
var checkRepoMaxBytes int64 = reposcan.DefaultMaxFileBytes

type writeEnvFile interface {
	WriteString(string) (int, error)
	Close() error
}

type writeEnvTempFile interface {
	Write([]byte) (int, error)
	Close() error
}

var (
	openWriteEnvTempFileFn = func(path string, flag int, perm os.FileMode) (writeEnvTempFile, error) {
		return os.OpenFile(path, flag, perm)
	}
	removeWriteEnvTempFileFn = os.Remove
	renameWriteEnvFileFn     = os.Rename
	manifestTargetDriftFn    = (*store.Handle).ManifestTargetDrift
	recordManifestReviewFn   = (*store.Handle).RecordManifestTargetReview
)

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
	targetName := fs.String("target", "", "")
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
	if *dryRun && !*explain {
		*explain = true
	}
	commandLabel := "run"
	if injectOnly {
		commandLabel = "inject"
	}
	targetExpansion := store.ManifestTargetExpansion{}
	if strings.TrimSpace(*targetName) != "" {
		if len(envRefs) > 0 || len(fileRefs) > 0 {
			return errors.New("--target cannot be combined with explicit --env or --file mappings")
		}
		target, err := brokerops.ExpandExecutionTarget(*projectRoot, strings.TrimSpace(*targetName), map[string]string(envRefs), map[string]string(fileRefs), command)
		if err != nil {
			return err
		}
		targetExpansion = target.Expansion
		envRefs = mappingFlag(target.EnvRefs)
		fileRefs = mappingFlag(target.FileRefs)
		command = slices.Clone(target.Command)
	}
	if len(command) == 0 && !*dryRun {
		return errors.New("usage: hasp run --project-root <path> [--target <name>|--env NAME=REF] [--file NAME=REF] [--session-token <token>] [--grant-project once|session|window|<duration>] [--grant-secret once|session|window|<duration>] [--grant-window 15m] [--explain [--dry-run]] -- <command>")
	}
	if injectOnly && len(fileRefs) == 0 {
		return errors.New("inject requires at least one --file NAME=REFERENCE mapping (use hasp run for env-only delivery)")
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
			Target:         strings.TrimSpace(*targetName),
			ManifestHash:   targetExpansion.ManifestHash,
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
	if err := warnTargetDrift(stderr, handle, *projectRoot, targetExpansion); err != nil {
		return err
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
	var swErr *redactor.StreamingWriter
	execResult, err := brokerops.Execute(ctx, brokerops.ExecutionRequest{
		Handle:           handle,
		BindingID:        binding.ID,
		ProjectRoot:      *projectRoot,
		SessionToken:     session.Token,
		Command:          command,
		EnvRefs:          map[string]string(envRefs),
		FileRefs:         map[string]string(fileRefs),
		Expansion:        targetExpansion,
		ProjectGrant:     projScope,
		SecretGrant:      secScope,
		Window:           effectiveWindow,
		AuthorizeWrapErr: wrapAuthorizeReferenceError,
		ConfigureRunner: func(items []store.Item, input runner.Input) runner.Input {
			if tty {
				swOut = redactor.NewStreamingWriterANSIAware(stdout, items)
			} else {
				swOut = redactor.NewStreamingWriter(stdout, items)
			}
			swErr = redactor.NewStreamingWriter(stderr, items)
			input.Stdin = deps.RunnerStdin
			input.Stdout = swOut
			input.Stderr = swErr
			input.TTY = tty
			return input
		},
		Deps: brokerops.ExecutionDeps{
			AuthorizeReference: deps.AuthorizeReference,
			RunnerExecute:      deps.RunnerExecute,
		},
	})
	// Flush streaming writers regardless of error so buffered bytes are
	// not silently dropped.
	var flushErrOut error
	var flushErrErr error
	if swOut != nil {
		flushErrOut = swOut.Flush()
	}
	if swErr != nil {
		flushErrErr = swErr.Flush()
	}
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
		details := map[string]any{
			"project_root":   *projectRoot,
			"redacted":       true,
			"suppressed":     false,
			"redacted_items": mergeRedactedItems(statsOut.MatchedItems, statsErr.MatchedItems),
		}
		addTargetAuditFields(details, targetExpansion)
		appendAudit(audit.EventRedact, "user", details)
	}
	result := execResult.RunResult
	runAudit := map[string]any{"project_root": *projectRoot, "exit_code": result.ExitCode, "args": command}
	addTargetAuditFields(runAudit, targetExpansion)
	appendAudit(audit.EventRun, "user", runAudit)
	if result.ExitCode != 0 {
		return fmt.Errorf("command exited with code %d", result.ExitCode)
	}
	if err := recordManifestReviewFn(handle, *projectRoot, targetExpansion); err != nil {
		return err
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
	targetName := fs.String("target", "", "")
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
	expandedRoot, err := expandUserPath(strings.TrimSpace(*projectRoot))
	if err != nil {
		return fmt.Errorf("--project-root: %w", err)
	}
	*projectRoot = expandedRoot
	targetExpansion := store.ManifestTargetExpansion{}
	lineSeparator := "="
	if strings.TrimSpace(*targetName) != "" {
		if len(envRefs) > 0 {
			return errors.New("--target cannot be combined with explicit --env mappings")
		}
		targetExpansion, err = store.ExpandManifestTarget(*projectRoot, *targetName)
		if err != nil {
			return err
		}
		if len(targetExpansion.Files) > 0 {
			return fmt.Errorf("target %q contains safe file delivery; use hasp inject --target", *targetName)
		}
		if len(targetExpansion.Env) > 0 && len(targetExpansion.XCConfig) > 0 {
			return fmt.Errorf("target %q mixes env and xcconfig delivery for write-env", *targetName)
		}
		if len(targetExpansion.XCConfig) > 0 {
			envRefs = mappingFlag(targetExpansion.XCConfig)
			lineSeparator = " = "
			if strings.TrimSpace(*outputPath) == "" {
				output, err := singleTargetOutput(targetExpansion)
				if err != nil {
					return err
				}
				if !filepath.IsAbs(output) {
					output = filepath.Join(*projectRoot, output)
				}
				*outputPath = output
			}
		} else {
			envRefs = mappingFlag(targetExpansion.Env)
		}
	}
	if *outputPath == "" || len(envRefs) == 0 {
		return errors.New("usage: hasp write-env --project-root <path> [--target <name>|--env NAME=REF] [--session-token <token>] --output <file> [--append] [--force] [--grant-project once|session|window|<duration>] [--grant-secret once|session|window|<duration>] [--grant-convenience once|window|<duration>]")
	}
	expandedOutput, err := expandUserPath(strings.TrimSpace(*outputPath))
	if err != nil {
		return fmt.Errorf("--output: %w", err)
	}
	*outputPath = expandedOutput
	if *forceMode && *appendMode {
		return errors.New("--force and --append are mutually exclusive")
	}
	warning, err := preflightWriteEnvDestination(ctx, *projectRoot, *outputPath, *appendMode, deps)
	if err != nil {
		return err
	}
	if warning != "" {
		_, _ = fmt.Fprintln(stderr, warning)
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
	if err := warnTargetDrift(stderr, handle, *projectRoot, targetExpansion); err != nil {
		return err
	}
	if err := brokerops.RequireReviewedTarget(handle, *projectRoot, targetExpansion); err != nil {
		return err
	}
	// Overwrite guard: when neither --force nor --append, refuse if file exists.
	if !*appendMode && !*forceMode {
		if _, statErr := os.Stat(*outputPath); statErr == nil {
			return fmt.Errorf("refusing to overwrite existing %s; pass --force to overwrite or --append to merge", *outputPath)
		}
	}

	lines, err := authorizeWriteEnvExport(ctx, handle, deps, writeEnvExportRequest{
		ProjectRoot:   *projectRoot,
		OutputPath:    *outputPath,
		BindingID:     binding.ID,
		SessionToken:  session.Token,
		EnvRefs:       map[string]string(envRefs),
		LineSeparator: lineSeparator,
		ProjectScope:  projScope,
		SecretScope:   secScope,
		Convenience:   convScope,
		Window:        effectiveWindow,
	})
	if err != nil {
		return err
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
		tmpFile, err := openWriteEnvTempFileFn(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		removeTmp := true
		defer func() {
			if removeTmp {
				_ = removeWriteEnvTempFileFn(tmpPath)
			}
		}()
		if _, err := tmpFile.Write(output); err != nil {
			_ = tmpFile.Close()
			return err
		}
		if err := tmpFile.Close(); err != nil {
			return err
		}
		if err := renameWriteEnvFileFn(tmpPath, *outputPath); err != nil {
			return err
		}
		removeTmp = false
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
	writeAudit := map[string]any{"project_root": *projectRoot, "output_path": *outputPath, "entries": len(lines), "warning": warning}
	addTargetAuditFields(writeAudit, targetExpansion)
	appendAudit(audit.EventWriteEnv, "user", writeAudit)
	payload := map[string]any{"output_path": *outputPath, "entries": len(lines), "warning": warning}
	if strings.TrimSpace(targetExpansion.TargetName) != "" {
		payload["target"] = targetExpansion.TargetName
		payload["manifest_hash"] = targetExpansion.ManifestHash
	}
	if err := recordManifestReviewFn(handle, *projectRoot, targetExpansion); err != nil {
		return err
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderWriteEnvResult(w, *outputPath, len(lines), warning)
	})
}

func checkRepoCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	return checkRepoCommandWithDeps(ctx, args, stdout, stderr, defaultExecDeps())
}

func preflightWriteEnvDestination(ctx context.Context, projectRoot string, outputPath string, appendMode bool, deps execDeps) (string, error) {
	if err := rejectWriteEnvSymlink(outputPath, "output path"); err != nil {
		return "", err
	}
	if appendMode {
		if err := rejectWriteEnvSymlink(outputPath+".tmp", "temporary output path"); err != nil {
			return "", err
		}
	}
	warning := ""
	root, err := store.CanonicalProjectRoot(ctx, projectRoot)
	if err == nil && pathInsideProjectForWrite(outputPath, root, deps) {
		warning = "destination is inside the bound project and outside the agent-safe guarantee"
	}
	return warning, nil
}

func rejectWriteEnvSymlink(path string, label string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write %s %s because it is a symlink; choose a regular file path", label, path)
		}
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("inspect %s %s: %w", label, path, err)
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
	vaultWarning := ""
	var items []store.Item
	if err != nil {
		if !errors.Is(err, store.ErrKeyringUnavailable) && !errors.Is(err, store.ErrVaultNotInitialized) {
			return err
		}
		vaultWarning = "vault unavailable; managed-value matching was skipped"
	} else {
		items = handle.ListItems()
	}
	root, err := appCanonicalProjectRootFn(ctx, *projectRoot)
	if err != nil {
		return err
	}
	noteResolvedProjectRootIfImplicit(fs, *jsonOutput, root, stderr)
	scanResult, err := reposcan.Scan(ctx, root, items, checkRepoMaxBytes, checkRepoScanDeps(deps))
	if err != nil {
		return err
	}
	matches := scanMatchesAsMaps(scanResult.Matches)
	payload := map[string]any{
		"matches":  matches,
		"override": *allowManagedSecrets,
		"skipped":  scanResult.Skipped,
		"walker":   scanResult.Walker,
	}
	if vaultWarning != "" {
		payload["warning"] = vaultWarning
		if !*jsonOutput {
			_, _ = fmt.Fprintln(stderr, "warning: "+vaultWarning)
		}
	}
	if len(matches) > 0 {
		appendAudit(audit.EventRepoBlock, "user", map[string]any{"project_root": root, "matches": len(matches), "override": *allowManagedSecrets})
		_ = renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
			return renderRepoCheckResult(w, root, matches, *allowManagedSecrets, vaultWarning)
		})
		if *allowManagedSecrets {
			return nil
		}
		return newAppError(errCodeRepoLeak, "managed secrets detected in repository files").
			withHint("re-run with --allow-managed-secrets if the override is intentional")
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderRepoCheckResult(w, root, matches, *allowManagedSecrets, vaultWarning)
	})
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
	return reposcan.Enumerate(ctx, root, checkRepoScanDeps(deps))
}

func checkRepoScanDeps(deps execDeps) reposcan.Deps {
	return reposcan.Deps{
		Stat:       os.Stat,
		ReadFile:   os.ReadFile,
		WalkDir:    deps.WalkProjectDir,
		GitLsFiles: deps.GitLsFiles,
		ByteIndex:  bytesIndex,
	}
}

func scanMatchesAsMaps(matches []reposcan.Match) []map[string]string {
	if len(matches) == 0 {
		return nil
	}
	out := make([]map[string]string, 0, len(matches))
	for _, match := range matches {
		out = append(out, map[string]string{"path": match.Path, "item_name": match.ItemName})
	}
	return out
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

func addTargetAuditFields(details map[string]any, expansion store.ManifestTargetExpansion) {
	if strings.TrimSpace(expansion.TargetName) == "" {
		return
	}
	details["target"] = expansion.TargetName
	details["manifest_hash"] = expansion.ManifestHash
	details["target_refs"] = expansion.Refs
	details["target_destinations"] = expansion.Destinations
	if strings.TrimSpace(expansion.TargetRoot) != "" {
		details["target_root"] = expansion.TargetRoot
	}
}

func warnTargetDrift(stderr io.Writer, handle *store.Handle, projectRoot string, expansion store.ManifestTargetExpansion) error {
	if strings.TrimSpace(expansion.TargetName) == "" {
		return nil
	}
	drift, err := manifestTargetDriftFn(handle, projectRoot, expansion)
	if err != nil {
		return err
	}
	if !drift.Changed {
		if !drift.Known {
			_, _ = fmt.Fprintf(stderr, "manifest target %q has not been locally reviewed; inspect the value-free target shape, then run `hasp project target review %s` before granting secrets.\n", expansion.TargetName, expansion.TargetName)
		}
		return nil
	}
	changes := make([]string, 0, 4)
	if drift.CommandChanged {
		changes = append(changes, "command")
	}
	if drift.RefsChanged {
		changes = append(changes, "refs")
	}
	if drift.DeliveryChanged {
		changes = append(changes, "delivery")
	}
	if drift.OutputsChanged {
		changes = append(changes, "outputs")
	}
	if len(changes) == 0 {
		changes = append(changes, "manifest")
	}
	_, _ = fmt.Fprintf(stderr, "manifest target %q changed since last local review: %s\n", expansion.TargetName, strings.Join(changes, ", "))
	return nil
}

func singleTargetOutput(expansion store.ManifestTargetExpansion) (string, error) {
	outputs := make([]string, 0, len(expansion.Outputs))
	seen := map[string]struct{}{}
	for _, output := range expansion.Outputs {
		output = strings.TrimSpace(output)
		if output == "" {
			continue
		}
		if _, ok := seen[output]; ok {
			continue
		}
		seen[output] = struct{}{}
		outputs = append(outputs, output)
	}
	sort.Strings(outputs)
	if len(outputs) != 1 {
		return "", fmt.Errorf("target %q must declare exactly one output for write-env", expansion.TargetName)
	}
	return outputs[0], nil
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

func pathInsideProjectForWrite(path string, root string, deps execDeps) bool {
	if pathInsideProjectWithDeps(path, root, deps) {
		return true
	}
	if root == "" {
		return false
	}
	absPath, err1 := deps.AbsPath(path)
	absRoot, err2 := deps.AbsPath(root)
	if err1 != nil || err2 != nil {
		return false
	}
	if resolvedRoot, err := deps.EvalSymlinks(absRoot); err == nil {
		absRoot = resolvedRoot
	}
	parts := []string{filepath.Base(absPath)}
	dir := filepath.Dir(absPath)
	for {
		if resolvedDir, err := deps.EvalSymlinks(dir); err == nil {
			for i := len(parts) - 1; i >= 0; i-- {
				resolvedDir = filepath.Join(resolvedDir, parts[i])
			}
			return resolvedDir == absRoot || strings.HasPrefix(resolvedDir, absRoot+string(filepath.Separator))
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		parts = append(parts, filepath.Base(dir))
		dir = parent
	}
}

// wrapAuthorizeReferenceError converts known broker errors into appError
// envelopes with actionable hints. Plain errors that don't match are
// returned unchanged so callers further up the stack can still inspect them.
func wrapAuthorizeReferenceError(err error) error {
	var notExposed *store.ReferenceNotExposedError
	if errors.As(err, &notExposed) {
		name := strings.TrimSpace(notExposed.ItemName)
		if name == "" {
			name = strings.TrimPrefix(strings.TrimSpace(notExposed.Reference), "@")
		}
		hint := "run `hasp secret expose --project-root . <NAME>` to expose the existing secret to this project"
		if name != "" {
			hint = fmt.Sprintf("run `hasp secret expose --project-root . %s` to expose this existing secret to the project", name)
		}
		return newAppError(errCodeUserInput, err.Error()).withHint(hint)
	}
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
