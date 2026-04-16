package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/mcp"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type setupOptionalBool struct {
	set   bool
	value bool
}

func (b *setupOptionalBool) String() string {
	if b == nil || !b.set {
		return ""
	}
	if b.value {
		return "true"
	}
	return "false"
}

func (b *setupOptionalBool) Set(value string) error {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "true", "1", "yes", "y":
		b.set = true
		b.value = true
	case "false", "0", "no", "n":
		b.set = true
		b.value = false
	default:
		return fmt.Errorf("expected true or false, got %q", value)
	}
	return nil
}

type setupAgentFlags []string

func (s *setupAgentFlags) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *setupAgentFlags) Set(value string) error {
	for _, raw := range strings.Split(value, ",") {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		*s = append(*s, id)
	}
	return nil
}

type setupOptions struct {
	NonInteractive          bool
	JSONOutput              bool
	HaspHome                string
	Repo                    string
	Agents                  setupAgentFlags
	AutoProtectRepos        setupOptionalBool
	PasswordEnv             string
	PasswordStdin           bool
	ImportPath              string
	ImportFormat            string
	BindImports             bool
	BindItems               stringListFlags
	Aliases                 aliasFlags
	DefaultPolicy           store.SecretPolicy
	InstallHooks            setupOptionalBool
	EnableConvenienceUnlock setupOptionalBool
	OverwriteExistingConfig setupOptionalBool
}

type setupAgentSpec struct {
	ID         string
	Label      string
	Format     string
	ConfigPath func(home string) string
}

type setupAgentOutcome struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	ConfigPath string `json:"config_path"`
	BackupPath string `json:"backup_path,omitempty"`
	Changed    bool   `json:"changed"`
}

type setupPlanPreview struct {
	HaspHome                string
	ProjectRoot             string
	Agents                  []setupAgentSpec
	AutoProtectRepos        bool
	ImportPath              string
	BindImports             bool
	InstallHooks            bool
	EnableConvenienceUnlock bool
	ConfigExists            bool
}

type setupSummary struct {
	HaspHome          string                   `json:"hasp_home"`
	ConfigPath        string                   `json:"config_path"`
	InitState         string                   `json:"init_state"`
	ProjectRoot       string                   `json:"project_root"`
	AutoProtectRepos  bool                     `json:"auto_protect_repos"`
	AutoInstallHooks  bool                     `json:"auto_install_hooks"`
	DefaultPolicy     store.SecretPolicy       `json:"default_policy"`
	Binding           *store.Binding           `json:"binding,omitempty"`
	Visible           []store.VisibleReference `json:"visible,omitempty"`
	ImportPreview     *importPreview           `json:"import_preview,omitempty"`
	Imported          []store.ImportedItem     `json:"imported,omitempty"`
	Agents            []setupAgentOutcome      `json:"agents,omitempty"`
	ConvenienceUnlock string                   `json:"convenience_unlock"`
	Verification      map[string]any           `json:"verification"`
	Notes             []string                 `json:"notes,omitempty"`
	NextSteps         []string                 `json:"next_steps,omitempty"`
}

type setupPrompter struct {
	reader *bufio.Reader
	out    io.Writer
	file   *os.File
}

var (
	setupUserHomeDirFn = os.UserHomeDir
	setupLookPathFn    = exec.LookPath
	setupReadFileFn    = os.ReadFile
	setupWriteFileFn   = os.WriteFile
	setupMkdirAllFn    = os.MkdirAll
	setupRenameFn      = os.Rename
	setupCreateTempFn  = os.CreateTemp
	setupAbsFn         = filepath.Abs
	setupTempDirFn     = os.TempDir
	setupTempWriteFn   = func(file *os.File, data []byte) (int, error) { return file.Write(data) }
	setupTempChmodFn   = func(file *os.File, mode os.FileMode) error { return file.Chmod(mode) }
	setupTempCloseFn   = func(file *os.File) error { return file.Close() }
	setupNowFn         = func() time.Time { return time.Now().UTC() }
	setupSttyFn        = func(file *os.File, args ...string) error {
		cmd := exec.Command("stty", args...)
		cmd.Stdin = file
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		return cmd.Run()
	}
	setupCanHideInputFn = func(file *os.File) bool {
		if file == nil {
			return false
		}
		info, err := file.Stat()
		if err != nil {
			return false
		}
		return info.Mode()&os.ModeCharDevice != 0
	}
	setupSaveConfigFn         = paths.SaveConfig
	setupConfigPathFn         = paths.ConfigPath
	setupLoadConfigFn         = paths.LoadConfig
	setupCanonicalProjectRoot = store.CanonicalProjectRoot
	setupResolvePasswordFn    = setupResolvePassword
	setupSetEnvFn             = setupSetEnv
	setupImportAndBindFn      = setupImportAndBind
	setupFinalizeBindingFn    = setupFinalizeBinding
	setupImportPathFn         = func(ctx context.Context, handle *store.Handle, path string, opts store.ImportOptions) (store.ImportResult, error) {
		return handle.ImportPath(ctx, path, opts)
	}
	setupWriteIntroFn          = setupWriteIntro
	setupWriteSelectedAgentsFn = setupWriteSelectedAgents
	setupWriteConfirmationFn   = setupWriteConfirmation
	setupResolveBindingViewFn  = func(ctx context.Context, handle *store.Handle, projectRoot string) (store.Binding, []store.VisibleReference, error) {
		return handle.ResolveBindingView(ctx, projectRoot)
	}
	setupEnableConvenienceUnlockFn = func(ctx context.Context, handle *store.Handle) error { return handle.EnableConvenienceUnlock(ctx) }
	setupWriteAgentConfigsFn       = setupWriteAgentConfigs
	setupVerifyHarnessFn           = setupVerifyHarness
	setupMCPServeFn                = mcp.Serve
	setupMCPToolNamesFn            = mcp.ToolNames
	setupGOOS                      = runtime.GOOS
)

func setupCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	opts, err := parseSetupOptions(args)
	if err != nil {
		return err
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

func parseSetupOptions(args []string) (setupOptions, error) {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	nonInteractive := fs.Bool("non-interactive", false, "")
	jsonOutput := fs.Bool("json", false, "")
	haspHome := fs.String("hasp-home", "", "")
	repo := fs.String("repo", "", "")
	passwordEnv := fs.String("master-password-env", "", "")
	passwordStdin := fs.Bool("master-password-stdin", false, "")
	importPath := fs.String("import", "", "")
	importFormat := fs.String("import-format", "auto", "")
	bindImports := fs.Bool("bind-imports", false, "")
	defaultPolicy := fs.String("default-policy", string(store.PolicySession), "")
	var agents setupAgentFlags
	var bindItems stringListFlags
	var aliases aliasFlags
	var installHooks setupOptionalBool
	var convenienceUnlock setupOptionalBool
	var overwriteExistingConfig setupOptionalBool
	var autoProtectRepos setupOptionalBool
	fs.Var(&agents, "agent", "agent id")
	fs.Var(&bindItems, "bind-item", "item name")
	fs.Var(&aliases, "alias", "alias=item")
	fs.Var(&autoProtectRepos, "auto-protect-repos", "true|false")
	fs.Var(&installHooks, "install-hooks", "true|false")
	fs.Var(&convenienceUnlock, "enable-convenience-unlock", "true|false")
	fs.Var(&overwriteExistingConfig, "overwrite-existing-config", "true|false")
	if err := fs.Parse(args); err != nil {
		return setupOptions{}, err
	}
	if fs.NArg() != 0 {
		return setupOptions{}, errors.New("usage: hasp setup [--hasp-home <path>] [--repo <path>] [--agent <id>] [--import <path>] [--bind-imports] [--non-interactive]")
	}
	if strings.TrimSpace(*passwordEnv) != "" && *passwordStdin {
		return setupOptions{}, errors.New("setup accepts only one password source")
	}
	if strings.TrimSpace(*importPath) == "-" && *passwordStdin {
		return setupOptions{}, errors.New("setup cannot use stdin for both password and import")
	}
	return setupOptions{
		NonInteractive:          *nonInteractive,
		JSONOutput:              *jsonOutput,
		HaspHome:                strings.TrimSpace(*haspHome),
		Repo:                    strings.TrimSpace(*repo),
		Agents:                  agents,
		AutoProtectRepos:        autoProtectRepos,
		PasswordEnv:             strings.TrimSpace(*passwordEnv),
		PasswordStdin:           *passwordStdin,
		ImportPath:              strings.TrimSpace(*importPath),
		ImportFormat:            strings.TrimSpace(*importFormat),
		BindImports:             *bindImports,
		BindItems:               bindItems,
		Aliases:                 aliases,
		DefaultPolicy:           store.SecretPolicy(strings.TrimSpace(*defaultPolicy)),
		InstallHooks:            installHooks,
		EnableConvenienceUnlock: convenienceUnlock,
		OverwriteExistingConfig: overwriteExistingConfig,
	}, nil
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
	if len(selectedAgents) == 0 {
		return setupSummary{}, errors.New("setup requires at least one supported agent")
	}
	if !opts.NonInteractive {
		if err := setupWriteSelectedAgentsFn(prompt.out, selectedAgents); err != nil {
			return setupSummary{}, err
		}
	}

	if err := setupResolveBoolOptions(&opts, prompt, selectedAgents); err != nil {
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
	handle, initState, err := setupEnsureHandle(ctx, vaultStore, password, vaultExists)
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

	convenienceState := "disabled"
	if opts.EnableConvenienceUnlock.value {
		if err := setupEnableConvenienceUnlockFn(ctx, handle); err != nil {
			if errors.Is(err, store.ErrKeyringUnavailable) {
				convenienceState = "unavailable"
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

	verification, err := setupVerifyHarnessFn(ctx, selectedAgents)
	if err != nil {
		return setupSummary{}, err
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
		Agents:            agentOutcomes,
		ConvenienceUnlock: convenienceState,
		Verification:      verification,
		Notes:             setupNotes(selectedAgents, configExists, opts, convenienceState),
		NextSteps:         setupNextSteps(projectRoot, binding, resolvedHome, convenienceState, opts.AutoProtectRepos.value, opts.InstallHooks.value),
	}
	if projectRoot != "" {
		summary.Binding = &binding
	}
	return summary, nil
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

func setupResolveHome(opts setupOptions, prompt *setupPrompter) (string, string, error) {
	configPath, err := setupConfigPathFn()
	if err != nil {
		return "", "", err
	}
	if opts.HaspHome != "" {
		path, err := expandHome(opts.HaspHome)
		if err != nil {
			return "", "", err
		}
		abs, err := setupAbsFn(path)
		if err != nil {
			return "", "", err
		}
		return filepath.Clean(abs), configPath, nil
	}
	cfg, err := setupLoadConfigFn()
	if err != nil {
		return "", "", err
	}
	defaultHome := strings.TrimSpace(cfg.HomeDir)
	if defaultHome != "" {
		if !setupSavedHomeLooksUsable(defaultHome) {
			defaultHome = ""
		}
	}
	if defaultHome == "" {
		defaultHome = defaultSetupHome()
	}
	if opts.NonInteractive {
		return defaultHome, configPath, nil
	}
	if err := setupWriteStage(prompt.out, "Machine setup",
		"Stores the encrypted vault, audit log, and runtime files outside your repo.",
		"Recommended default: ~/.hasp",
	); err != nil {
		return "", "", err
	}
	value, err := promptStringWithDisplayDefault(prompt, "Local HASP data directory", defaultHome, setupDisplayPath(defaultHome))
	if err != nil {
		return "", "", err
	}
	expanded, err := expandHome(value)
	if err != nil {
		return "", "", err
	}
	abs, err := setupAbsFn(expanded)
	if err != nil {
		return "", "", err
	}
	return filepath.Clean(abs), configPath, nil
}

func defaultSetupHome() string {
	home, err := setupUserHomeDirFn()
	if err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".hasp")
	}
	if home := strings.TrimSpace(os.Getenv(paths.EnvHome)); home != "" {
		return home
	}
	return ".hasp"
}

func setupResolveProjectRoot(ctx context.Context, opts setupOptions, prompt *setupPrompter) (string, error) {
	if opts.Repo != "" {
		return setupCanonicalProjectRoot(ctx, opts.Repo)
	}
	defaultRoot, err := setupCanonicalProjectRoot(ctx, ".")
	if err != nil {
		return "", err
	}
	if opts.NonInteractive {
		return "", errors.New("non-interactive setup requires --repo")
	}
	if err := setupWriteStage(prompt.out, "Repo setup",
		"HASP will protect this repo with brokered bindings and optional local guardrails.",
	); err != nil {
		return "", err
	}
	value, err := promptString(prompt, "Repository root to protect", defaultRoot)
	if err != nil {
		return "", err
	}
	return setupCanonicalProjectRoot(ctx, value)
}

func setupResolveAgents(opts setupOptions, prompt *setupPrompter) ([]setupAgentSpec, error) {
	supported := setupSupportedAgents()
	if len(opts.Agents) > 0 {
		return selectSetupAgents(supported, []string(opts.Agents))
	}
	detected := detectSetupAgents(supported)
	defaultIDs := setupDefaultAgentIDs(detected)
	if opts.NonInteractive {
		return nil, errors.New("non-interactive setup requires at least one --agent")
	}
	if err := setupWriteAgentMenu(prompt.out, supported, defaultIDs); err != nil {
		return nil, err
	}
	defaultSelection := setupDefaultAgentSelection(supported, defaultIDs)
	value, err := promptString(prompt, "Select agents to configure (numbers separated by commas)", defaultSelection)
	if err != nil {
		return nil, err
	}
	selected, err := parseSetupAgentMenuSelection(supported, value)
	if err != nil {
		return nil, err
	}
	return selectSetupAgents(supported, selected)
}

func setupResolveBoolOptions(opts *setupOptions, prompt *setupPrompter, agents []setupAgentSpec) error {
	if !opts.AutoProtectRepos.set {
		if opts.NonInteractive {
			opts.AutoProtectRepos = setupOptionalBool{set: true, value: true}
		} else {
			if err := setupWriteStage(prompt.out, "Repo coverage",
				"HASP can automatically protect projects the first time you use it in them.",
				"Repo scope still stays local and project-specific under the hood.",
			); err != nil {
				return err
			}
			value, err := promptBool(prompt, "Automatically protect projects on first use", true)
			if err != nil {
				return err
			}
			opts.AutoProtectRepos = setupOptionalBool{set: true, value: value}
		}
	}
	if !opts.InstallHooks.set {
		if opts.NonInteractive {
			opts.InstallHooks = setupOptionalBool{set: true, value: true}
		} else {
			label := "Install repo guardrails automatically for new repos"
			if !opts.AutoProtectRepos.value {
				label = "Install repo guardrails automatically if you later enable auto-protect"
			}
			value, err := promptBool(prompt, label, true)
			if err != nil {
				return err
			}
			opts.InstallHooks = setupOptionalBool{set: true, value: value}
		}
	}
	if !opts.EnableConvenienceUnlock.set {
		if opts.NonInteractive {
			opts.EnableConvenienceUnlock = setupOptionalBool{set: true, value: defaultSetupConvenienceUnlock()}
		} else {
			value, err := promptBool(prompt, "Use convenience unlock on this machine when available", defaultSetupConvenienceUnlock())
			if err != nil {
				return err
			}
			opts.EnableConvenienceUnlock = setupOptionalBool{set: true, value: value}
		}
	}
	if opts.ImportPath == "" && !opts.NonInteractive {
		if err := setupWriteStage(prompt.out, "Optional import",
			"You can import a local .env or JSON secret file now, or skip this and use `hasp import` later.",
		); err != nil {
			return err
		}
		shouldImport, err := promptBool(prompt, "Import a local secret file now", false)
		if err != nil {
			return err
		}
		if !shouldImport {
			goto maybeOverwrite
		}
		value, err := promptString(prompt, "Path to .env or JSON secret file", "")
		if err != nil {
			return err
		}
		opts.ImportPath = strings.TrimSpace(value)
	}
	if opts.ImportPath != "" && !opts.BindImports && !opts.NonInteractive && strings.TrimSpace(opts.Repo) != "" {
		value, err := promptBool(prompt, "Bind imported secrets to this repository now", true)
		if err != nil {
			return err
		}
		opts.BindImports = value
	}
maybeOverwrite:
	if setupAnyExistingAgentConfig(agents) && !opts.OverwriteExistingConfig.set {
		if opts.NonInteractive {
			return errors.New("non-interactive setup requires --overwrite-existing-config=true|false when agent config files already exist")
		}
		value, err := promptBool(prompt, "Allow HASP to update existing agent config files and create backups", true)
		if err != nil {
			return err
		}
		opts.OverwriteExistingConfig = setupOptionalBool{set: true, value: value}
	}
	return nil
}

func validateSetupNonInteractive(opts setupOptions) error {
	if !opts.NonInteractive {
		return nil
	}
	if opts.HaspHome == "" {
		return errors.New("non-interactive setup requires --hasp-home")
	}
	if len(opts.Agents) == 0 {
		return errors.New("non-interactive setup requires at least one --agent")
	}
	if opts.PasswordEnv == "" && !opts.PasswordStdin {
		return errors.New("non-interactive setup requires --master-password-env or --master-password-stdin")
	}
	return nil
}

func setupValidateHomePath(home string, projectRoot string) error {
	info, err := os.Lstat(home)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("HASP home cannot be a symlink: %s", home)
		}
		if !info.IsDir() {
			return fmt.Errorf("HASP home must be a directory path: %s", home)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("HASP home must not be group or world accessible: %s", home)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if withinPath(home, projectRoot) {
		return errors.New("HASP home cannot live inside the project directory")
	}
	return nil
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
		password := strings.TrimSpace(string(data))
		if password == "" {
			return "", vaultExists, errors.New("master password from stdin is empty")
		}
		return password, vaultExists, nil
	case opts.NonInteractive:
		return "", vaultExists, errors.New("non-interactive setup requires a master password source")
	}

	if vaultExists {
		password, err := promptPassword(prompt, "Enter your HASP master password")
		if err != nil {
			return "", vaultExists, err
		}
		if strings.TrimSpace(password) == "" {
			return "", vaultExists, errors.New("master password is required")
		}
		return password, vaultExists, nil
	}

	for {
		first, err := promptPassword(prompt, "Choose a local HASP master password")
		if err != nil {
			return "", vaultExists, err
		}
		second, err := promptPassword(prompt, "Confirm master password")
		if err != nil {
			return "", vaultExists, err
		}
		if first != second {
			if _, err := fmt.Fprintln(prompt.out, "Master passwords did not match. Try again."); err != nil {
				return "", vaultExists, err
			}
			continue
		}
		if strings.TrimSpace(first) == "" {
			return "", vaultExists, errors.New("master password is required")
		}
		return first, vaultExists, nil
	}
}

func setupVaultExists(home string) bool {
	_, err := os.Stat(filepath.Join(home, "vault.json.enc"))
	return err == nil
}

func setupEnsureHandle(ctx context.Context, vaultStore *store.Store, password string, vaultExists bool) (*store.Handle, string, error) {
	if vaultExists {
		handle, err := openStoreWithPasswordFn(ctx, vaultStore, password)
		if err != nil {
			return nil, "", err
		}
		return handle, "existing", nil
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

func setupImportInput(prompt *setupPrompter, opts setupOptions) io.Reader {
	if opts.ImportPath == "-" {
		return prompt.reader
	}
	return nil
}

func setupImportAndBind(ctx context.Context, handle *store.Handle, projectRoot string, opts setupOptions, prompt *setupPrompter) ([]store.ImportedItem, error) {
	imported := []store.ImportedItem{}
	if opts.ImportPath != "" {
		prepared, err := prepareImport(opts.ImportPath, opts.ImportFormat, "", setupImportInput(prompt, opts), opts.BindImports, nil)
		if err != nil {
			return nil, err
		}
		defer prepared.Cleanup()
		result, err := setupImportPathFn(ctx, handle, prepared.Path, store.ImportOptions{
			ProjectRoot:   projectRoot,
			BindToProject: opts.BindImports,
		})
		if err != nil {
			return nil, err
		}
		imported = append(imported, result.Imported...)
	}
	for alias, item := range opts.Aliases {
		if _, err := handle.GetItem(item); err != nil {
			return nil, err
		}
		opts.Aliases[alias] = item
	}
	for _, itemName := range opts.BindItems {
		alias, err := handle.BindItemAlias(ctx, projectRoot, itemName)
		if err != nil {
			return nil, err
		}
		imported = append(imported, store.ImportedItem{Name: itemName, Alias: alias})
	}
	return imported, nil
}

func setupFinalizeBinding(ctx context.Context, handle *store.Handle, projectRoot string, opts setupOptions) (store.Binding, []store.VisibleReference, error) {
	aliases := cloneAliasSet(opts.Aliases)
	current, visible, err := setupResolveBindingViewFn(ctx, handle, projectRoot)
	if err == nil {
		for alias, item := range current.Aliases {
			aliases[alias] = item
		}
		_ = visible
	}
	if _, err := bindProject(ctx, handle, projectRoot, aliases, opts.DefaultPolicy, opts.InstallHooks.value); err != nil {
		return store.Binding{}, nil, err
	}
	binding, visible, err := setupResolveBindingViewFn(ctx, handle, projectRoot)
	return binding, visible, err
}

func setupSupportedAgents() []setupAgentSpec {
	home, _ := setupUserHomeDirFn()
	return []setupAgentSpec{
		{
			ID:     "codex-cli",
			Label:  "Codex CLI",
			Format: "toml",
			ConfigPath: func(_ string) string {
				return filepath.Join(home, ".codex", "config.toml")
			},
		},
		{
			ID:     "claude-code",
			Label:  "Claude Code",
			Format: "json",
			ConfigPath: func(_ string) string {
				return filepath.Join(home, ".claude.json")
			},
		},
		{
			ID:     "cursor",
			Label:  "Cursor",
			Format: "json",
			ConfigPath: func(_ string) string {
				return filepath.Join(home, ".cursor", "mcp.json")
			},
		},
	}
}

func detectSetupAgents(supported []setupAgentSpec) []setupAgentSpec {
	detected := []setupAgentSpec{}
	for _, spec := range supported {
		if _, err := setupLookPathFn(setupAgentBinary(spec.ID)); err == nil {
			detected = append(detected, spec)
			continue
		}
		if _, err := os.Stat(spec.ConfigPath("")); err == nil {
			detected = append(detected, spec)
		}
	}
	return detected
}

func selectSetupAgents(supported []setupAgentSpec, ids []string) ([]setupAgentSpec, error) {
	selected := []setupAgentSpec{}
	seen := map[string]struct{}{}
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		idx := slices.IndexFunc(supported, func(spec setupAgentSpec) bool { return spec.ID == id })
		if idx < 0 {
			return nil, fmt.Errorf("unsupported setup agent %q", id)
		}
		selected = append(selected, supported[idx])
		seen[id] = struct{}{}
	}
	return selected, nil
}

func setupAgentBinary(id string) string {
	switch id {
	case "codex-cli":
		return "codex"
	case "claude-code":
		return "claude"
	case "cursor":
		return "cursor"
	default:
		return id
	}
}

func setupAnyExistingAgentConfig(agents []setupAgentSpec) bool {
	for _, agent := range agents {
		if _, err := os.Lstat(agent.ConfigPath("")); err == nil {
			return true
		}
	}
	return false
}

func setupWriteAgentConfigs(agents []setupAgentSpec, haspHome string) ([]setupAgentOutcome, error) {
	outcomes := make([]setupAgentOutcome, 0, len(agents))
	for _, agent := range agents {
		path := agent.ConfigPath("")
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("agent config path is a symlink: %s", path)
		}
		var existing []byte
		if err == nil {
			existing, err = setupReadFileFn(path)
			if err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}

		var updated []byte
		switch agent.Format {
		case "toml":
			updated = []byte(upsertCodexMCPServerConfig(existing, haspHome))
		case "json":
			updated, err = upsertJSONMCPServerConfig(existing, haspHome)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported setup config format %q", agent.Format)
		}

		backupPath, changed, err := setupAtomicWrite(path, existing, updated)
		if err != nil {
			return nil, err
		}
		outcomes = append(outcomes, setupAgentOutcome{
			ID:         agent.ID,
			Label:      agent.Label,
			ConfigPath: path,
			BackupPath: backupPath,
			Changed:    changed,
		})
	}
	return outcomes, nil
}

func upsertCodexMCPServerConfig(existing []byte, haspHome string) string {
	blockLines := []string{
		"[mcp_servers.hasp]",
		"command = \"hasp\"",
		"args = [\"mcp\"]",
	}
	if strings.TrimSpace(haspHome) != "" {
		blockLines = append(blockLines,
			"[mcp_servers.hasp.env]",
			"HASP_HOME = "+strconvQuote(haspHome),
		)
	}
	block := strings.Join(blockLines, "\n") + "\n"
	content := strings.TrimRight(string(existing), "\n")
	if content == "" {
		return block
	}
	lines := strings.Split(content, "\n")
	out := []string{}
	skipping := false
	inserted := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[mcp_servers.hasp]" || trimmed == "[mcp_servers.hasp.env]" {
			if !inserted {
				out = append(out, strings.TrimRight(block, "\n"))
				inserted = true
			}
			skipping = true
			continue
		}
		if skipping && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			skipping = false
		}
		if skipping {
			continue
		}
		out = append(out, line)
	}
	if !inserted {
		out = append(out, "", strings.TrimRight(block, "\n"))
	}
	return strings.TrimLeft(strings.Join(out, "\n"), "\n") + "\n"
}

func upsertJSONMCPServerConfig(existing []byte, haspHome string) ([]byte, error) {
	config := map[string]any{}
	if len(bytes.TrimSpace(existing)) > 0 {
		if err := json.Unmarshal(existing, &config); err != nil {
			return nil, err
		}
	}
	mcpServers := map[string]any{}
	if existingServers, ok := config["mcpServers"]; ok {
		typed, ok := existingServers.(map[string]any)
		if !ok {
			return nil, errors.New("existing mcpServers value is not an object")
		}
		mcpServers = typed
	}
	serverConfig := map[string]any{
		"command": "hasp",
		"args":    []string{"mcp"},
	}
	if strings.TrimSpace(haspHome) != "" {
		serverConfig["env"] = map[string]string{"HASP_HOME": haspHome}
	}
	mcpServers["hasp"] = serverConfig
	config["mcpServers"] = mcpServers
	data, _ := json.MarshalIndent(config, "", "  ")
	return append(data, '\n'), nil
}

func setupAtomicWrite(path string, existing []byte, updated []byte) (string, bool, error) {
	if bytes.Equal(existing, updated) {
		return "", false, nil
	}
	if err := setupMkdirAllFn(filepath.Dir(path), 0o700); err != nil {
		return "", false, err
	}
	backupPath := ""
	if len(existing) > 0 {
		backupPath = fmt.Sprintf("%s.bak.%s", path, setupNowFn().Format("20060102-150405"))
		if err := setupWriteFileFn(backupPath, existing, 0o600); err != nil {
			return "", false, err
		}
	}
	tempFile, err := setupCreateTempFn(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return backupPath, false, err
	}
	tempName := tempFile.Name()
	defer os.Remove(tempName)
	if _, err := setupTempWriteFn(tempFile, updated); err != nil {
		_ = setupTempCloseFn(tempFile)
		return backupPath, false, err
	}
	if err := setupTempChmodFn(tempFile, 0o600); err != nil {
		_ = setupTempCloseFn(tempFile)
		return backupPath, false, err
	}
	if err := setupTempCloseFn(tempFile); err != nil {
		return backupPath, false, err
	}
	if err := setupRenameFn(tempName, path); err != nil {
		return backupPath, false, err
	}
	return backupPath, true, nil
}

func setupVerifyHarness(ctx context.Context, agents []setupAgentSpec) (map[string]any, error) {
	request := bytes.NewBufferString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n")
	var output bytes.Buffer
	if err := setupMCPServeFn(ctx, request, &output); err != nil {
		return nil, err
	}
	if !strings.Contains(output.String(), "hasp_list") {
		return nil, errors.New("setup verification failed: hasp_list missing from MCP tools/list")
	}
	agentIDs := make([]string, 0, len(agents))
	for _, agent := range agents {
		agentIDs = append(agentIDs, agent.ID)
	}
	return map[string]any{
		"mcp": map[string]any{
			"ready": true,
			"tools": setupMCPToolNamesFn(),
		},
		"agents": agentIDs,
	}, nil
}

func setupNotes(agents []setupAgentSpec, configExisted bool, opts setupOptions, convenienceState string) []string {
	notes := []string{
		"setup writes only local MCP config stanzas for selected agents",
		"setup never writes secret values into agent config, repo files, or shell profiles",
		"convenience materialization remains an explicit separate path via hasp write-env",
	}
	if configExisted {
		notes = append(notes, "existing agent config files were backed up before mutation")
	}
	if opts.BindImports {
		notes = append(notes, "imported items were bound only because bind-imports was explicitly requested")
	}
	if convenienceState == "unavailable" {
		notes = append(notes, "convenience unlock was requested but the keyring was unavailable")
	}
	for _, agent := range agents {
		notes = append(notes, "configured agent target: "+agent.ID)
	}
	return notes
}

func setupNextSteps(projectRoot string, binding store.Binding, haspHome string, convenienceState string, autoProtect bool, autoInstallHooks bool) []string {
	steps := []string{
		"verify MCP with: printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\\n' | hasp mcp",
	}
	if strings.TrimSpace(projectRoot) != "" {
		steps = append(steps, "review the repo binding with: hasp project status --project-root \""+projectRoot+"\"")
	}
	if strings.TrimSpace(projectRoot) != "" && len(binding.Aliases) > 0 {
		steps = append(steps, "test one brokered command with: hasp run --project-root \""+projectRoot+"\" --env NAME=<alias> --grant-project window --grant-secret session --grant-window 15m -- your-command")
	} else {
		steps = append(steps, "the first time you use HASP in a project, it will adopt that project automatically")
		steps = append(steps, "inspect an adopted repo with: hasp project status --project-root /path/to/repo")
	}
	if convenienceState != "enabled" {
		steps = append(steps, "future CLI commands still need HASP_MASTER_PASSWORD unless you rerun setup and enable convenience unlock")
	}
	steps = append(steps, "saved CLI config keeps HASP_HOME at "+haspHome)
	return steps
}

func renderSetupSummary(out io.Writer, summary setupSummary) error {
	if err := setupWriteStage(out, "Setup complete",
		"HASP is configured for this machine.",
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Local HASP data: %s\n", summary.HaspHome); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Saved CLI config: %s\n", summary.ConfigPath); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Automatic repo adoption: %s\n", setupEnabledDisabled(summary.AutoProtectRepos)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Automatic repo guardrails: %s\n", setupYesNo(summary.AutoInstallHooks)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Vault state: %s\n", summary.InitState); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Convenience unlock: %s\n", summary.ConvenienceUnlock); err != nil {
		return err
	}
	if strings.TrimSpace(summary.ProjectRoot) != "" {
		if _, err := fmt.Fprintf(out, "Protected repository: %s\n", summary.ProjectRoot); err != nil {
			return err
		}
	}
	if len(summary.Agents) > 0 {
		if _, err := fmt.Fprintln(out, "Configured agents:"); err != nil {
			return err
		}
		for _, agent := range summary.Agents {
			suffix := "updated"
			if !agent.Changed {
				suffix = "unchanged"
			}
			if _, err := fmt.Fprintf(out, "- %s -> %s (%s)\n", agent.Label, agent.ConfigPath, suffix); err != nil {
				return err
			}
		}
	}
	if len(summary.NextSteps) > 0 {
		if _, err := fmt.Fprintln(out, "Next steps:"); err != nil {
			return err
		}
		for _, step := range summary.NextSteps {
			if _, err := fmt.Fprintf(out, "- %s\n", step); err != nil {
				return err
			}
		}
	}
	return nil
}

func setupWriteIntro(out io.Writer) error {
	return setupWriteStage(out, "HASP setup",
		"HASP setup will:",
		"1. choose where local encrypted HASP data lives on this machine",
		"2. set defaults for automatically protecting repos on first use",
		"3. configure selected coding agents to talk to HASP over MCP",
		"Press Enter to accept the default shown in brackets.",
	)
}

func setupWriteStage(out io.Writer, title string, lines ...string) error {
	if _, err := fmt.Fprintf(out, "== %s ==\n", title); err != nil {
		return err
	}
	for _, line := range lines {
		if _, err := fmt.Fprintf(out, "  %s\n", line); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	return nil
}

func setupWriteSelectedAgents(out io.Writer, agents []setupAgentSpec) error {
	if len(agents) == 0 {
		return nil
	}
	lines := make([]string, 0, len(agents)+1)
	lines = append(lines, "Selected agent config targets:")
	for _, agent := range agents {
		lines = append(lines, fmt.Sprintf("- %s -> %s", agent.Label, agent.ConfigPath("")))
	}
	return setupWriteStage(out, "Agent targets", lines...)
}

func setupWriteAgentMenu(out io.Writer, supported []setupAgentSpec, defaultIDs []string) error {
	lines := []string{
		"Pick which coding agents HASP should configure for MCP.",
		"Enter numbers like 1 or 1,3. Existing config files are backed up before mutation.",
	}
	defaultSet := map[string]struct{}{}
	for _, id := range defaultIDs {
		defaultSet[id] = struct{}{}
	}
	for idx, agent := range supported {
		suffix := ""
		if _, ok := defaultSet[agent.ID]; ok {
			suffix = " [default]"
		}
		lines = append(lines, fmt.Sprintf("%d. %s%s", idx+1, agent.Label, suffix))
		lines = append(lines, fmt.Sprintf("   config: %s", setupDisplayPath(agent.ConfigPath(""))))
	}
	return setupWriteStage(out, "Agent setup", lines...)
}

func setupDefaultAgentIDs(detected []setupAgentSpec) []string {
	defaultIDs := make([]string, 0, len(detected))
	for _, spec := range detected {
		defaultIDs = append(defaultIDs, spec.ID)
	}
	if len(defaultIDs) == 0 {
		defaultIDs = []string{"codex-cli"}
	}
	return defaultIDs
}

func setupDefaultAgentSelection(supported []setupAgentSpec, defaultIDs []string) string {
	indexes := make([]string, 0, len(defaultIDs))
	for _, id := range defaultIDs {
		for idx, spec := range supported {
			if spec.ID == id {
				indexes = append(indexes, strconv.Itoa(idx+1))
				break
			}
		}
	}
	if len(indexes) == 0 {
		return "1"
	}
	return strings.Join(indexes, ",")
}

func parseSetupAgentMenuSelection(supported []setupAgentSpec, value string) ([]string, error) {
	selected := []string{}
	seen := map[string]struct{}{}
	for _, raw := range strings.Split(value, ",") {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		if index, err := strconv.Atoi(token); err == nil {
			if index < 1 || index > len(supported) {
				return nil, fmt.Errorf("unsupported setup agent selection %q", token)
			}
			id := supported[index-1].ID
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			selected = append(selected, id)
			continue
		}
		idx := slices.IndexFunc(supported, func(spec setupAgentSpec) bool { return spec.ID == token })
		if idx < 0 {
			return nil, fmt.Errorf("unsupported setup agent selection %q", token)
		}
		id := supported[idx].ID
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		selected = append(selected, id)
	}
	return selected, nil
}

func setupWriteConfirmation(out io.Writer, plan setupPlanPreview) error {
	lines := []string{
		fmt.Sprintf("Local HASP data: %s", setupDisplayPath(plan.HaspHome)),
		fmt.Sprintf("Automatic repo adoption: %s", setupEnabledDisabled(plan.AutoProtectRepos)),
		fmt.Sprintf("Install repo guardrails: %s", setupYesNo(plan.InstallHooks)),
		fmt.Sprintf("Convenience unlock: %s", setupEnabledDisabled(plan.EnableConvenienceUnlock)),
	}
	if strings.TrimSpace(plan.ProjectRoot) != "" {
		lines = append(lines, fmt.Sprintf("Protect this repo now: %s", plan.ProjectRoot))
	}
	if strings.TrimSpace(plan.ImportPath) == "" {
		lines = append(lines, "Import during setup: skip for now")
	} else {
		lines = append(lines, fmt.Sprintf("Import during setup: %s", plan.ImportPath))
		lines = append(lines, fmt.Sprintf("Bind imported secrets now: %s", setupYesNo(plan.BindImports)))
	}
	if plan.ConfigExists {
		lines = append(lines, "Existing agent config files will be updated with backups.")
	}
	if len(plan.Agents) > 0 {
		lines = append(lines, "Agent config targets:")
		for _, agent := range plan.Agents {
			lines = append(lines, fmt.Sprintf("- %s -> %s", agent.Label, setupDisplayPath(agent.ConfigPath(""))))
		}
	}
	return setupWriteStage(out, "Review before apply", lines...)
}

func setupConfirmPlan(prompt *setupPrompter, plan setupPlanPreview) error {
	if err := setupWriteConfirmationFn(prompt.out, plan); err != nil {
		return err
	}
	proceed, err := promptBool(prompt, "Apply these changes now", true)
	if err != nil {
		return err
	}
	if !proceed {
		return errors.New("setup cancelled before making changes")
	}
	return nil
}

func setupDisplayPath(path string) string {
	home, err := setupUserHomeDirFn()
	if err != nil {
		return path
	}
	if path == home {
		return "~"
	}
	prefix := home + string(filepath.Separator)
	if strings.HasPrefix(path, prefix) {
		return "~" + string(filepath.Separator) + strings.TrimPrefix(path, prefix)
	}
	return path
}

func setupSavedHomeLooksUsable(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false
	} else if err != nil {
		return false
	}
	tempRoot := strings.TrimSpace(setupTempDirFn())
	if tempRoot == "" {
		return true
	}
	absPath, err := setupAbsFn(path)
	if err != nil {
		return false
	}
	absTemp, err := setupAbsFn(tempRoot)
	if err != nil {
		return false
	}
	if absPath == absTemp || strings.HasPrefix(absPath, absTemp+string(filepath.Separator)) {
		return false
	}
	return true
}

func defaultSetupConvenienceUnlock() bool {
	return setupGOOS == "darwin"
}

func setupBoolPointer(value bool) *bool {
	v := value
	return &v
}

func setupYesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func setupEnabledDisabled(value bool) string {
	if value {
		return "enabled when available"
	}
	return "disabled"
}

func promptString(prompt *setupPrompter, label string, defaultValue string) (string, error) {
	return promptStringWithDisplayDefault(prompt, label, defaultValue, defaultValue)
}

func promptStringWithDisplayDefault(prompt *setupPrompter, label string, defaultValue string, displayDefault string) (string, error) {
	if defaultValue != "" {
		if _, err := fmt.Fprintf(prompt.out, "%s [%s]: ", label, displayDefault); err != nil {
			return "", err
		}
	} else {
		if _, err := fmt.Fprintf(prompt.out, "%s: ", label); err != nil {
			return "", err
		}
	}
	line, err := prompt.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if _, err := fmt.Fprintln(prompt.out); err != nil {
		return "", err
	}
	value := strings.TrimSpace(line)
	if value == "" {
		return defaultValue, nil
	}
	return value, nil
}

func promptBool(prompt *setupPrompter, label string, defaultValue bool) (bool, error) {
	defaultLabel := "y/N"
	if defaultValue {
		defaultLabel = "Y/n"
	}
	value, err := promptString(prompt, label, defaultLabel)
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "", strings.ToLower(defaultLabel):
		return defaultValue, nil
	case "y", "yes", "true", "1":
		return true, nil
	case "n", "no", "false", "0":
		return false, nil
	default:
		return defaultValue, nil
	}
}

func promptPassword(prompt *setupPrompter, label string) (string, error) {
	if prompt.file == nil || !setupCanHideInputFn(prompt.file) {
		return promptString(prompt, label+" (input is visible)", "")
	}
	if _, err := fmt.Fprintf(prompt.out, "%s: ", label); err != nil {
		return "", err
	}
	if err := setupSttyFn(prompt.file, "-echo"); err != nil {
		return promptString(prompt, label+" (input is visible)", "")
	}
	defer func() {
		_ = setupSttyFn(prompt.file, "echo")
		_, _ = fmt.Fprintln(prompt.out)
	}()
	line, err := prompt.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func setupSetEnv(name string, value string) (func(), error) {
	previous, had := os.LookupEnv(name)
	if err := os.Setenv(name, value); err != nil {
		return nil, err
	}
	return func() {
		if had {
			_ = os.Setenv(name, previous)
			return
		}
		_ = os.Unsetenv(name)
	}, nil
}

func expandHome(value string) (string, error) {
	if value == "~" || strings.HasPrefix(value, "~/") {
		home, err := setupUserHomeDirFn()
		if err != nil {
			return "", err
		}
		if value == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(value, "~/")), nil
	}
	return value, nil
}

func withinPath(path string, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func strconvQuote(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}
