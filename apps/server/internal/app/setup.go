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
	"slices"
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
	HaspHome                string
	Repo                    string
	Agents                  setupAgentFlags
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

type setupSummary struct {
	HaspHome          string                   `json:"hasp_home"`
	ConfigPath        string                   `json:"config_path"`
	InitState         string                   `json:"init_state"`
	ProjectRoot       string                   `json:"project_root"`
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
	setupResolveBindingViewFn = func(ctx context.Context, handle *store.Handle, projectRoot string) (store.Binding, []store.VisibleReference, error) {
		return handle.ResolveBindingView(ctx, projectRoot)
	}
	setupEnableConvenienceUnlockFn = func(ctx context.Context, handle *store.Handle) error { return handle.EnableConvenienceUnlock(ctx) }
	setupWriteAgentConfigsFn       = setupWriteAgentConfigs
	setupVerifyHarnessFn           = setupVerifyHarness
	setupMCPServeFn                = mcp.Serve
	setupMCPToolNamesFn            = mcp.ToolNames
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
	return json.NewEncoder(stdout).Encode(summary)
}

func parseSetupOptions(args []string) (setupOptions, error) {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	nonInteractive := fs.Bool("non-interactive", false, "")
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
	fs.Var(&agents, "agent", "agent id")
	fs.Var(&bindItems, "bind-item", "item name")
	fs.Var(&aliases, "alias", "alias=item")
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
		HaspHome:                strings.TrimSpace(*haspHome),
		Repo:                    strings.TrimSpace(*repo),
		Agents:                  agents,
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

	resolvedHome, configPath, err := setupResolveHome(opts, prompt)
	if err != nil {
		return setupSummary{}, err
	}
	opts.HaspHome = resolvedHome

	projectRoot, err := setupResolveProjectRoot(ctx, opts, prompt)
	if err != nil {
		return setupSummary{}, err
	}
	opts.Repo = projectRoot
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

	if err := setupResolveBoolOptions(&opts, prompt, selectedAgents); err != nil {
		return setupSummary{}, err
	}
	if err := validateSetupNonInteractive(opts); err != nil {
		return setupSummary{}, err
	}

	configExists := setupAnyExistingAgentConfig(selectedAgents)
	if configExists && !opts.OverwriteExistingConfig.value {
		return setupSummary{}, errors.New("setup aborted because overwrite approval was denied for existing agent config files")
	}

	password, vaultExists, err := setupResolvePasswordFn(prompt, opts, resolvedHome)
	if err != nil {
		return setupSummary{}, err
	}

	if err := setupSaveConfigFn(paths.CLIConfig{HomeDir: resolvedHome}); err != nil {
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
	if existingBinding, _, err := setupResolveBindingViewFn(ctx, handle, projectRoot); err == nil {
		currentAliases = cloneAliasSet(existingBinding.Aliases)
	}

	var preview *importPreview
	if opts.ImportPath != "" {
		prepared, err := prepareImport(opts.ImportPath, opts.ImportFormat, "", setupImportInput(prompt, opts), opts.BindImports, currentAliases)
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

	binding, visible, err := setupFinalizeBindingFn(ctx, handle, projectRoot, opts)
	if err != nil {
		return setupSummary{}, err
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
		Binding:           &binding,
		Visible:           visible,
		ImportPreview:     preview,
		Imported:          imported,
		Agents:            agentOutcomes,
		ConvenienceUnlock: convenienceState,
		Verification:      verification,
		Notes:             setupNotes(selectedAgents, configExists, opts, convenienceState),
		NextSteps:         setupNextSteps(projectRoot, binding, resolvedHome, convenienceState),
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
	if defaultHome == "" {
		defaultHome = defaultSetupHome()
	}
	if opts.NonInteractive {
		return defaultHome, configPath, nil
	}
	value, err := promptString(prompt, "HASP vault directory", defaultHome)
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
	resolved, err := paths.Resolve()
	if err == nil && strings.TrimSpace(resolved.HomeDir) != "" {
		return resolved.HomeDir
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
	value, err := promptString(prompt, "Project directory to bind", defaultRoot)
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
	defaultIDs := make([]string, 0, len(detected))
	for _, spec := range detected {
		defaultIDs = append(defaultIDs, spec.ID)
	}
	if len(defaultIDs) == 0 {
		defaultIDs = []string{"codex-cli"}
	}
	if opts.NonInteractive {
		return nil, errors.New("non-interactive setup requires at least one --agent")
	}
	choices := []string{}
	for _, spec := range supported {
		choices = append(choices, spec.ID)
	}
	value, err := promptString(prompt, "Coding agents ("+strings.Join(choices, ", ")+")", strings.Join(defaultIDs, ","))
	if err != nil {
		return nil, err
	}
	var flags setupAgentFlags
	_ = flags.Set(value)
	return selectSetupAgents(supported, []string(flags))
}

func setupResolveBoolOptions(opts *setupOptions, prompt *setupPrompter, agents []setupAgentSpec) error {
	if !opts.InstallHooks.set {
		if opts.NonInteractive {
			return errors.New("non-interactive setup requires --install-hooks=true|false")
		}
		value, err := promptBool(prompt, "Install repo hooks", true)
		if err != nil {
			return err
		}
		opts.InstallHooks = setupOptionalBool{set: true, value: value}
	}
	if !opts.EnableConvenienceUnlock.set {
		if opts.NonInteractive {
			return errors.New("non-interactive setup requires --enable-convenience-unlock=true|false")
		}
		value, err := promptBool(prompt, "Enable convenience unlock on this machine", false)
		if err != nil {
			return err
		}
		opts.EnableConvenienceUnlock = setupOptionalBool{set: true, value: value}
	}
	if opts.ImportPath == "" && !opts.NonInteractive {
		value, err := promptString(prompt, "Import one local secret file now (optional path, blank to skip)", "")
		if err != nil {
			return err
		}
		opts.ImportPath = strings.TrimSpace(value)
	}
	if opts.ImportPath != "" && !opts.BindImports && !opts.NonInteractive {
		value, err := promptBool(prompt, "Bind imported items to the repo", true)
		if err != nil {
			return err
		}
		opts.BindImports = value
	}
	if setupAnyExistingAgentConfig(agents) && !opts.OverwriteExistingConfig.set {
		if opts.NonInteractive {
			return errors.New("non-interactive setup requires --overwrite-existing-config=true|false when agent config files already exist")
		}
		value, err := promptBool(prompt, "Update existing agent config files with backups", true)
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
	if opts.Repo == "" {
		return errors.New("non-interactive setup requires --repo")
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

	first, err := promptPassword(prompt, "Choose a local HASP master password")
	if err != nil {
		return "", vaultExists, err
	}
	second, err := promptPassword(prompt, "Confirm master password")
	if err != nil {
		return "", vaultExists, err
	}
	if first != second {
		return "", vaultExists, errors.New("master password confirmation does not match")
	}
	if strings.TrimSpace(first) == "" {
		return "", vaultExists, errors.New("master password is required")
	}
	return first, vaultExists, nil
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

func setupNextSteps(projectRoot string, binding store.Binding, haspHome string, convenienceState string) []string {
	steps := []string{
		"verify MCP with: printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\\n' | hasp mcp",
		"review the repo binding with: hasp project status --project-root \"" + projectRoot + "\"",
	}
	if len(binding.Aliases) > 0 {
		steps = append(steps, "test one brokered command with: hasp run --project-root \""+projectRoot+"\" --env NAME=<alias> --grant-project window --grant-secret session --grant-window 15m -- your-command")
	}
	if convenienceState != "enabled" {
		steps = append(steps, "future CLI commands still need HASP_MASTER_PASSWORD unless you rerun setup and enable convenience unlock")
	}
	steps = append(steps, "saved CLI config keeps HASP_HOME at "+haspHome)
	return steps
}

func promptString(prompt *setupPrompter, label string, defaultValue string) (string, error) {
	if defaultValue != "" {
		if _, err := fmt.Fprintf(prompt.out, "%s [%s]: ", label, defaultValue); err != nil {
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
