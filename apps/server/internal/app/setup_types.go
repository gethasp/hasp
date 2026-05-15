package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/mcp"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type setupOptionalBool struct {
	set    bool
	value  bool
	source string
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
	case "always", "true", "1", "yes", "y", "on":
		b.set = true
		b.value = true
		b.source = "always"
	case "never", "false", "0", "no", "n", "off":
		b.set = true
		b.value = false
		b.source = "never"
	case "ask":
		b.set = false
		b.value = false
		b.source = "ask"
	default:
		return fmt.Errorf("expected always|never|ask (got %q)", value)
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
	Telemetry               setupOptionalBool
	SkipPasswordPolicy      bool
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
	Telemetry               bool
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
	AddedSecrets      []secretMutationView     `json:"added_secrets,omitempty"`
	Apps              []setupAppOutcome        `json:"apps,omitempty"`
	Agents            []setupAgentOutcome      `json:"agents,omitempty"`
	ConvenienceUnlock string                   `json:"convenience_unlock"`
	ConvenienceDetail string                   `json:"convenience_detail,omitempty"`
	Telemetry         string                   `json:"telemetry"`
	Verification      map[string]any           `json:"verification"`
	Notes             []string                 `json:"notes,omitempty"`
	NextSteps         []string                 `json:"next_steps,omitempty"`
}

type setupAppOutcome struct {
	Name         string              `json:"name"`
	ProjectRoot  string              `json:"project_root,omitempty"`
	LauncherPath string              `json:"launcher_path,omitempty"`
	PathUpdate   appPathUpdateResult `json:"path_update,omitempty"`
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
	setupExecutableFn         = os.Executable
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
	setupVerifyConvenienceUnlockFn = func(ctx context.Context, vaultStore *store.Store) error {
		_, err := vaultStore.OpenWithConvenienceUnlock(ctx)
		return err
	}
	setupWriteAgentConfigsFn      = setupWriteAgentConfigs
	setupVerifyHarnessFn          = setupVerifyHarness
	setupVerifyBrokeredProofFn    = setupVerifyBrokeredProof
	setupMCPServeFn               = mcp.Serve
	setupMCPToolNamesFn           = mcp.ToolNames
	setupConvenienceUnlockTimeout = 30 * time.Second
	setupConvenienceVerifyRetries = 3
	setupConvenienceRetryDelay    = 200 * time.Millisecond
	setupSleepFn                  = time.Sleep
	setupGOOS                     = runtime.GOOS
)
