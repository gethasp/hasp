package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
	"github.com/gethasp/hasp/apps/server/internal/telemetry"
)

func setupCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	opts, repoFlagUsed, err := parseSetupOptions(args)
	if err != nil {
		return err
	}
	if repoFlagUsed {
		// hasp-uxcn: --repo is the legacy flag; --project-root is canonical
		// across the rest of the CLI. Surface a one-time deprecation note
		// so existing scripts keep working but newcomers learn the unified
		// spelling.
		emitDeprecationWarning(ctx, stderr, "[hasp] 'hasp setup --repo' is deprecated; use --project-root instead.\n")
	}
	summary, err := runSetup(ctx, opts, stdin, stderr)
	if err != nil {
		return err
	}
	if !opts.NonInteractive && !opts.JSONOutput {
		return renderSetupSummary(stdout, summary)
	}
	return json.NewEncoder(stdout).Encode(summary)
}

func parseSetupOptions(args []string) (setupOptions, bool, error) {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	nonInteractive := fs.Bool("non-interactive", false, "")
	jsonOutput := fs.Bool("json", false, "")
	haspHome := fs.String("hasp-home", "", "")
	repo := fs.String("repo", "", "")
	// hasp-uxcn: --project-root is the canonical spelling shared with run,
	// inject, and the secret commands. --repo is kept as a back-compat alias
	// (deprecation warning emitted by setupCommand when --repo was used).
	projectRoot := fs.String("project-root", "", "")
	passwordEnv := fs.String("master-password-env", "", "")
	passwordStdin := fs.Bool("master-password-stdin", false, "")
	importPath := fs.String("import", "", "")
	importFormat := fs.String("import-format", "auto", "")
	bindImports := fs.Bool("bind-imports", false, "")
	defaultPolicy := fs.String("default-policy", string(store.PolicySession), "")
	skipPasswordPolicy := fs.Bool("skip-password-policy", false, "")
	var agents setupAgentFlags
	var bindItems stringListFlags
	var aliases aliasFlags
	var installHooks setupOptionalBool
	var convenienceUnlock setupOptionalBool
	var overwriteExistingConfig setupOptionalBool
	var autoProtectRepos setupOptionalBool
	var telemetryOpt setupOptionalBool
	fs.Var(&agents, "agent", "agent id")
	fs.Var(&bindItems, "bind-item", "item name")
	fs.Var(&aliases, "alias", "alias=item")
	fs.Var(&autoProtectRepos, "auto-protect-repos", "always|never|ask")
	fs.Var(&installHooks, "install-hooks", "always|never|ask")
	fs.Var(&convenienceUnlock, "enable-convenience-unlock", "always|never|ask")
	fs.Var(&overwriteExistingConfig, "overwrite-existing-config", "always|never|ask")
	fs.Var(&telemetryOpt, "telemetry", "always|never|ask")
	if err := fs.Parse(args); err != nil {
		return setupOptions{}, false, err
	}
	if fs.NArg() != 0 {
		// hasp-28um: generate the usage line from the FlagSet so it stays in
		// sync with the actual flag surface (no more "lists 6 of 17 flags").
		return setupOptions{}, false, errors.New(buildUsageLine("setup", fs))
	}
	if strings.TrimSpace(*passwordEnv) != "" && *passwordStdin {
		return setupOptions{}, false, errors.New("setup accepts only one password source")
	}
	if strings.TrimSpace(*importPath) == "-" && *passwordStdin {
		return setupOptions{}, false, errors.New("setup cannot use stdin for both password and import")
	}
	repoTrimmed := strings.TrimSpace(*repo)
	projectRootTrimmed := strings.TrimSpace(*projectRoot)
	if repoTrimmed != "" && projectRootTrimmed != "" && repoTrimmed != projectRootTrimmed {
		return setupOptions{}, false, errors.New("--repo and --project-root are aliases; supply only one (--project-root preferred)")
	}
	repoFlagUsed := repoTrimmed != "" && projectRootTrimmed == ""
	chosen := projectRootTrimmed
	if chosen == "" {
		chosen = repoTrimmed
	}
	expandedRepo := chosen
	if expandedRepo != "" {
		var expandErr error
		expandedRepo, expandErr = expandUserPath(expandedRepo)
		if expandErr != nil {
			label := "--project-root"
			if repoFlagUsed {
				label = "--repo"
			}
			return setupOptions{}, false, fmt.Errorf("%s: %w", label, expandErr)
		}
	}
	expandedImport := strings.TrimSpace(*importPath)
	if expandedImport != "" && expandedImport != "-" {
		var expandErr error
		expandedImport, expandErr = expandUserPath(expandedImport)
		if expandErr != nil {
			return setupOptions{}, false, fmt.Errorf("--import: %w", expandErr)
		}
	}
	return setupOptions{
		NonInteractive:          *nonInteractive,
		JSONOutput:              *jsonOutput,
		HaspHome:                strings.TrimSpace(*haspHome),
		Repo:                    expandedRepo,
		Agents:                  agents,
		AutoProtectRepos:        autoProtectRepos,
		PasswordEnv:             strings.TrimSpace(*passwordEnv),
		PasswordStdin:           *passwordStdin,
		ImportPath:              expandedImport,
		ImportFormat:            strings.TrimSpace(*importFormat),
		BindImports:             *bindImports,
		BindItems:               bindItems,
		Aliases:                 aliases,
		DefaultPolicy:           store.SecretPolicy(strings.TrimSpace(*defaultPolicy)),
		InstallHooks:            installHooks,
		EnableConvenienceUnlock: convenienceUnlock,
		OverwriteExistingConfig: overwriteExistingConfig,
		Telemetry:               telemetryOpt,
		SkipPasswordPolicy:      *skipPasswordPolicy,
	}, repoFlagUsed, nil
}

func runSetup(ctx context.Context, opts setupOptions, stdin io.Reader, promptOut io.Writer) (setupSummary, error) {
	prompt := newSetupPrompter(stdin, promptOut)
	if !opts.NonInteractive && promptOut != nil {
		if err := setupWriteIntroFn(prompt.out); err != nil {
			return setupSummary{}, err
		}
	}

	resolvedHome, configPath, err := setupResolveHome(opts, prompt)
	if err != nil {
		return setupSummary{}, err
	}
	opts.HaspHome = resolvedHome

	projectRoot := ""
	if strings.TrimSpace(opts.Repo) != "" {
		projectRoot, err = setupResolveProjectRoot(ctx, opts, prompt)
		if err != nil {
			return setupSummary{}, err
		}
		opts.Repo = projectRoot
	}
	if err := setupValidateHomePath(resolvedHome, projectRoot); err != nil {
		return setupSummary{}, err
	}

	selectedAgents, err := setupResolveAgents(opts, prompt)
	if err != nil {
		return setupSummary{}, err
	}
	if !opts.NonInteractive {
		if err := setupWriteSelectedAgentsFn(prompt.out, selectedAgents); err != nil {
			return setupSummary{}, err
		}
	}

	if err := setupResolveBoolOptions(&opts, prompt, selectedAgents); err != nil {
		return setupSummary{}, err
	}
	err = setupResolveTelemetryOption(&opts, prompt)
	if err != nil {
		return setupSummary{}, err
	}
	if err := validateProjectScopedSetupOptions(opts); err != nil {
		return setupSummary{}, err
	}
	if err := validateSetupNonInteractive(opts); err != nil {
		return setupSummary{}, err
	}

	configExists := setupAnyExistingAgentConfig(selectedAgents)
	if configExists && !opts.OverwriteExistingConfig.value {
		return setupSummary{}, errors.New("setup aborted because overwrite approval was denied for existing agent config files")
	}
	if !opts.NonInteractive {
		if err := setupConfirmPlan(prompt, setupPlanPreview{
			HaspHome:                resolvedHome,
			ProjectRoot:             projectRoot,
			Agents:                  selectedAgents,
			AutoProtectRepos:        opts.AutoProtectRepos.value,
			ImportPath:              opts.ImportPath,
			BindImports:             opts.BindImports,
			InstallHooks:            opts.InstallHooks.value,
			EnableConvenienceUnlock: opts.EnableConvenienceUnlock.value,
			Telemetry:               opts.Telemetry.value,
			ConfigExists:            configExists,
		}); err != nil {
			return setupSummary{}, err
		}
	}

	password, vaultExists, err := setupResolvePasswordFn(prompt, opts, resolvedHome)
	if err != nil {
		return setupSummary{}, err
	}

	if err := setupSaveConfigFn(paths.CLIConfig{
		HomeDir:              resolvedHome,
		AutoProtectRepos:     setupBoolPointer(opts.AutoProtectRepos.value),
		AutoInstallHooks:     setupBoolPointer(opts.InstallHooks.value),
		DefaultCapturePolicy: string(opts.DefaultPolicy),
	}); err != nil {
		return setupSummary{}, err
	}
	restoreHome, err := setupSetEnvFn(paths.EnvHome, resolvedHome)
	if err != nil {
		return setupSummary{}, err
	}
	defer restoreHome()

	vaultStore, err := newVaultStoreFn()
	if err != nil {
		return setupSummary{}, err
	}
	handle, initState, _, err := setupOpenHandleWithRetry(ctx, prompt, vaultStore, password, vaultExists, opts.NonInteractive, opts.SkipPasswordPolicy)
	if err != nil {
		return setupSummary{}, err
	}

	currentAliases := map[string]string{}
	if projectRoot != "" {
		if existingBinding, _, err := setupResolveBindingViewFn(ctx, handle, projectRoot); err == nil {
			currentAliases = cloneAliasSet(existingBinding.Aliases)
		}
	}

	var preview *importPreview
	if opts.ImportPath != "" {
		prepared, err := prepareImport(opts.ImportPath, opts.ImportFormat, "", setupImportInput(prompt, opts), opts.BindImports && projectRoot != "", currentAliases)
		if err != nil {
			return setupSummary{}, err
		}
		defer prepared.Cleanup()
		preview = &prepared.Preview
	}

	imported, err := setupImportAndBindFn(ctx, handle, projectRoot, opts, prompt)
	if err != nil {
		return setupSummary{}, err
	}

	var (
		binding store.Binding
		visible []store.VisibleReference
	)
	if projectRoot != "" {
		binding, visible, err = setupFinalizeBindingFn(ctx, handle, projectRoot, opts)
		if err != nil {
			return setupSummary{}, err
		}
	}
	addedSecrets := []secretMutationView{}
	apps := []setupAppOutcome{}
	if !opts.NonInteractive {
		addedSecrets, apps, err = setupOptionalFirstRunActions(ctx, prompt, handle, projectRoot)
		if err != nil {
			return setupSummary{}, err
		}
	}

	convenienceState := "disabled"
	convenienceDetail := ""
	if opts.EnableConvenienceUnlock.value {
		if err := setupRunConvenienceUnlockStep(ctx, func(stepCtx context.Context) error {
			return setupEnableConvenienceUnlockFn(stepCtx, handle)
		}); err != nil {
			if setupConvenienceUnlockUnavailable(err) {
				convenienceState = "unavailable"
				convenienceDetail = setupConvenienceUnlockDetail(err)
				if setupConvenienceUnlockRequired(opts) {
					return setupSummary{}, setupConvenienceUnlockRequiredError(convenienceDetail)
				}
			} else {
				return setupSummary{}, err
			}
		} else if err := setupRunConvenienceUnlockStep(ctx, func(stepCtx context.Context) error {
			return setupVerifyConvenienceUnlockWithRetry(stepCtx, vaultStore)
		}); err != nil {
			if setupConvenienceUnlockUnavailable(err) {
				convenienceState = "unavailable"
				convenienceDetail = setupConvenienceUnlockDetail(err)
				if setupConvenienceUnlockRequired(opts) {
					return setupSummary{}, setupConvenienceUnlockRequiredError(convenienceDetail)
				}
			} else {
				return setupSummary{}, err
			}
		} else {
			convenienceState = "enabled"
		}
	}

	agentOutcomes, err := setupWriteAgentConfigsFn(selectedAgents, resolvedHome)
	if err != nil {
		return setupSummary{}, err
	}
	for _, outcome := range agentOutcomes {
		if _, err := storeUpsertAgentFn(handle, store.AgentConsumer{
			Name:        outcome.ID,
			AgentID:     outcome.ID,
			ProjectRoot: projectRoot,
			ConfigPath:  outcome.ConfigPath,
		}); err != nil {
			return setupSummary{}, err
		}
	}

	verification, err := setupVerifyHarnessFn(ctx, selectedAgents)
	if err != nil {
		return setupSummary{}, err
	}
	brokeredProof, err := setupVerifyBrokeredProofFn(ctx, projectRoot, visible)
	if err != nil {
		brokeredProof = map[string]any{
			"performed": false,
			"ready":     false,
			"reason":    err.Error(),
		}
	}
	verification["brokered_proof"] = brokeredProof
	telemetryState := "disabled"
	if opts.Telemetry.value {
		if telemetry.DisabledByEnv() {
			telemetryState = "blocked_by_env"
		} else if _, err := telemetry.DefaultStore().Enable(setupNowFn().UTC()); err != nil {
			return setupSummary{}, err
		} else {
			telemetryState = "enabled"
		}
	}

	summary := setupSummary{
		HaspHome:          resolvedHome,
		ConfigPath:        configPath,
		InitState:         initState,
		ProjectRoot:       projectRoot,
		AutoProtectRepos:  opts.AutoProtectRepos.value,
		AutoInstallHooks:  opts.InstallHooks.value,
		DefaultPolicy:     opts.DefaultPolicy,
		Visible:           visible,
		ImportPreview:     preview,
		Imported:          imported,
		AddedSecrets:      addedSecrets,
		Apps:              apps,
		Agents:            agentOutcomes,
		ConvenienceUnlock: convenienceState,
		ConvenienceDetail: convenienceDetail,
		Telemetry:         telemetryState,
		Verification:      verification,
		Notes:             setupNotes(selectedAgents, configExists, opts, convenienceState, convenienceDetail),
		NextSteps:         setupNextSteps(projectRoot, binding, resolvedHome, convenienceState, convenienceDetail, opts.AutoProtectRepos.value, opts.InstallHooks.value),
	}
	if projectRoot != "" {
		summary.Binding = &binding
	}
	return summary, nil
}

func setupRunConvenienceUnlockStep(ctx context.Context, step func(context.Context) error) error {
	if setupConvenienceUnlockTimeout <= 0 {
		return step(ctx)
	}
	stepCtx, cancel := context.WithTimeout(ctx, setupConvenienceUnlockTimeout)
	defer cancel()
	return step(stepCtx)
}

func setupConvenienceUnlockUnavailable(err error) bool {
	return errors.Is(err, store.ErrKeyringUnavailable) || errors.Is(err, context.DeadlineExceeded)
}

func setupVerifyConvenienceUnlockWithRetry(ctx context.Context, vaultStore *store.Store) error {
	attempts := setupConvenienceVerifyRetries
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 0; ; attempt++ {
		err := setupVerifyConvenienceUnlockFn(ctx, vaultStore)
		if err == nil {
			return nil
		}
		if !setupConvenienceUnlockUnavailable(err) || attempt >= attempts-1 {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		setupSleepFn(setupConvenienceRetryDelay)
	}
}

func setupConvenienceUnlockDetail(err error) string {
	if err == nil {
		return ""
	}
	text := strings.TrimSpace(err.Error())
	if text == "" {
		return ""
	}
	if text == store.ErrKeyringUnavailable.Error() || errors.Is(err, context.DeadlineExceeded) {
		return "macOS keychain access did not complete during setup"
	}
	if strings.HasPrefix(text, store.ErrKeyringUnavailable.Error()+":") {
		return strings.TrimSpace(strings.TrimPrefix(text, store.ErrKeyringUnavailable.Error()+":"))
	}
	return text
}

func setupConvenienceUnlockRequired(opts setupOptions) bool {
	return opts.EnableConvenienceUnlock.value && opts.EnableConvenienceUnlock.source == "always"
}

func setupConvenienceUnlockRequiredError(detail string) error {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return errors.New("convenience unlock was required but is unavailable")
	}
	return fmt.Errorf("convenience unlock was required but is unavailable: %s", setupConvenienceDetailForDisplay(detail))
}

func setupConvenienceDetailForDisplay(detail string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return ""
	}
	lower := strings.ToLower(detail)
	if strings.Contains(lower, "keychain") {
		return "macOS login keychain access failed (this is not your HASP master password): " + detail
	}
	return detail
}

func setupOpenHandleWithRetry(ctx context.Context, prompt *setupPrompter, vaultStore *store.Store, password string, vaultExists bool, nonInteractive bool, skipPasswordPolicy bool) (*store.Handle, string, string, error) {
	for {
		handle, initState, err := setupEnsureHandle(ctx, vaultStore, password, vaultExists, skipPasswordPolicy)
		if err == nil {
			return handle, initState, password, nil
		}
		if !vaultExists || nonInteractive || !errors.Is(err, store.ErrInvalidPassword) {
			return nil, "", password, err
		}
		if _, writeErr := fmt.Fprintln(prompt.out, "invalid master password"); writeErr != nil {
			return nil, "", password, writeErr
		}
		password, err = setupPromptExistingVaultPassword(prompt)
		if err != nil {
			return nil, "", password, err
		}
	}
}

func newSetupPrompter(stdin io.Reader, out io.Writer) *setupPrompter {
	if stdin == nil {
		stdin = os.Stdin
	}
	if out == nil {
		out = io.Discard
	}
	prompt := &setupPrompter{
		reader: bufio.NewReader(stdin),
		out:    out,
	}
	if file, ok := stdin.(*os.File); ok {
		prompt.file = file
	}
	return prompt
}

func setupResolvePassword(prompt *setupPrompter, opts setupOptions, home string) (string, bool, error) {
	vaultExists := setupVaultExists(home)
	switch {
	case opts.PasswordEnv != "":
		password := os.Getenv(opts.PasswordEnv)
		if strings.TrimSpace(password) == "" {
			return "", vaultExists, fmt.Errorf("master password env %q is empty", opts.PasswordEnv)
		}
		return password, vaultExists, nil
	case opts.PasswordStdin:
		data, err := io.ReadAll(prompt.reader)
		if err != nil {
			return "", vaultExists, err
		}
		password := string(data)
		if strings.TrimSpace(password) == "" {
			return "", vaultExists, errors.New("master password from stdin is empty")
		}
		return password, vaultExists, nil
	case opts.NonInteractive:
		return "", vaultExists, errors.New("non-interactive setup requires a master password; set HASP_MASTER_PASSWORD or run without --non-interactive")
	}

	if vaultExists {
		password, err := setupPromptExistingVaultPassword(prompt)
		if err != nil {
			return "", vaultExists, err
		}
		return password, vaultExists, nil
	}

	for {
		first, err := setupPromptRequiredPassword(prompt, "Choose a local HASP master password")
		if err != nil {
			return "", vaultExists, err
		}
		second, err := setupPromptRequiredPassword(prompt, "Confirm master password")
		if err != nil {
			return "", vaultExists, err
		}
		if first != second {
			if _, err := fmt.Fprintln(prompt.out, "Master passwords did not match. Try again."); err != nil {
				return "", vaultExists, err
			}
			continue
		}
		if !opts.SkipPasswordPolicy {
			if err := store.EnforcePasswordPolicy(first); err != nil {
				if _, writeErr := fmt.Fprintf(prompt.out, "%v Try again.\n", err); writeErr != nil {
					return "", vaultExists, writeErr
				}
				continue
			}
		}
		return first, vaultExists, nil
	}
}

func setupPromptExistingVaultPassword(prompt *setupPrompter) (string, error) {
	return setupPromptRequiredPassword(prompt, "Enter your HASP master password")
}

func setupPromptRequiredPassword(prompt *setupPrompter, label string) (string, error) {
	for {
		password, emptyEOF, err := promptPasswordAttempt(prompt, label)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(password) != "" {
			return password, nil
		}
		if _, err := fmt.Fprintln(prompt.out, "Master password is required. Try again."); err != nil {
			return "", err
		}
		if emptyEOF && !setupCanRepeatPasswordAfterEOF(prompt) {
			return "", errors.New("master password is required")
		}
	}
}

func setupCanRepeatPasswordAfterEOF(prompt *setupPrompter) bool {
	if prompt == nil || prompt.file == nil {
		return false
	}
	info, err := prompt.file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func setupVaultExists(home string) bool {
	_, err := os.Stat(filepath.Join(home, "vault.json.enc"))
	return err == nil
}

func setupEnsureHandle(ctx context.Context, vaultStore *store.Store, password string, vaultExists bool, skipPasswordPolicy bool) (*store.Handle, string, error) {
	if vaultExists {
		handle, err := openStoreWithPasswordFn(ctx, vaultStore, password)
		if err != nil {
			return nil, "", err
		}
		return handle, "existing", nil
	}
	if !skipPasswordPolicy {
		if err := store.EnforcePasswordPolicy(password); err != nil {
			return nil, "", err
		}
	}
	if err := vaultStore.Init(ctx, password); err != nil {
		return nil, "", err
	}
	handle, err := openStoreWithPasswordFn(ctx, vaultStore, password)
	if err != nil {
		return nil, "", err
	}
	return handle, "created", nil
}
