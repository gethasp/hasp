package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

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
	if defaultHome != "" && !setupSavedHomeLooksUsable(defaultHome) {
		defaultHome = ""
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
		return "", errors.New("non-interactive setup requires --project-root")
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
		return nil, nil
	}
	if err := setupWriteAgentMenu(prompt.out, supported, defaultIDs); err != nil {
		return nil, err
	}
	defaultSelection := setupDefaultAgentSelection(supported, nil)
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
			opts.EnableConvenienceUnlock = setupOptionalBool{set: true, value: defaultSetupConvenienceUnlock(), source: "default"}
		} else {
			value, err := promptBool(prompt, "Use convenience unlock on this machine when available", defaultSetupConvenienceUnlock())
			if err != nil {
				return err
			}
			opts.EnableConvenienceUnlock = setupOptionalBool{set: true, value: value, source: "prompt"}
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
			return errors.New("non-interactive setup requires --overwrite-existing-config=always|never when agent config files already exist")
		}
		value, err := promptBool(prompt, "Allow HASP to update existing agent config files and create backups", true)
		if err != nil {
			return err
		}
		opts.OverwriteExistingConfig = setupOptionalBool{set: true, value: value}
	}
	return nil
}

func setupResolveTelemetryOption(opts *setupOptions, prompt *setupPrompter) error {
	if opts.Telemetry.set {
		return nil
	}
	if opts.NonInteractive {
		opts.Telemetry = setupOptionalBool{set: true, value: false}
		return nil
	}
	if err := setupWriteStage(prompt.out, "Telemetry",
		"HASP CLI telemetry is optional and disabled by default.",
		"It sends daily aggregate command and reliability counters only.",
		"It never sends secrets, secret names, aliases, refs, paths, repo names, command args, stdout/stderr, raw errors, or audit logs.",
		"Set HASP_TELEMETRY_DISABLED=1 to block telemetry at runtime.",
	); err != nil {
		return err
	}
	value, err := promptBool(prompt, "Allow optional HASP CLI telemetry", false)
	if err != nil {
		return err
	}
	opts.Telemetry = setupOptionalBool{set: true, value: value}
	return nil
}

func validateSetupNonInteractive(opts setupOptions) error {
	if !opts.NonInteractive {
		return nil
	}
	if opts.HaspHome == "" {
		return errors.New("non-interactive setup requires --hasp-home")
	}
	if opts.PasswordEnv == "" && !opts.PasswordStdin {
		return errors.New("non-interactive setup requires a master password; set HASP_MASTER_PASSWORD or run without --non-interactive")
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
