package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/ttyutil"
	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/redactor"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var (
	appResolvePathsFn    = paths.Resolve
	appWriteFileFn       = os.WriteFile
	appReadFileFn        = os.ReadFile
	appMkdirAllFn        = os.MkdirAll
	appRemoveFn          = os.Remove
	appUserShellFn       = func() string { return os.Getenv("SHELL") }
	appCurrentShellFn    = func() string { return os.Getenv("SHELL") }
	appUserHomeDirFn     = os.UserHomeDir
	storeGetAppFn        = (*store.Handle).GetAppConsumer
	storeListAppsFn      = (*store.Handle).ListAppConsumers
	storeUpsertAppFn     = (*store.Handle).UpsertAppConsumer
	storeDeleteAppFn     = (*store.Handle).DeleteAppConsumer
	appExecuteConsumerFn = executeAppConsumer
	appInstallLauncherFn = installAppLauncher
)

func appConsumerCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, s starter) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		return printHelpTopic(stdout, []string{"app"})
	}
	if len(args) > 1 && isHelpArg(args[1]) {
		return printHelpTopic(stdout, []string{"app", args[0]})
	}
	switch args[0] {
	case "connect":
		return appConnectCommandWithInput(ctx, args[1:], stdin, stdout, stderr)
	case "run":
		return appRunCommand(ctx, args[1:], stdout, stderr, s)
	case "install":
		return appInstallCommandWithInput(ctx, args[1:], stdin, stdout, stderr)
	case "shell":
		return appShellCommand(ctx, args[1:], stdout, stderr, s)
	case "disconnect":
		return appDisconnectCommand(ctx, args[1:], stdout)
	case "list":
		return appListCommand(ctx, args[1:], stdout)
	default:
		return fmt.Errorf("unknown app subcommand %q", args[0])
	}
}

func appConnectCommand(ctx context.Context, args []string, stdout io.Writer) error {
	return appConnectCommandWithInput(ctx, args, nil, stdout, io.Discard)
}

func appConnectCommandWithInput(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	name, remaining := consumerNameAndArgs(args)
	fs := flag.NewFlagSet("app connect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", "", "")
	command := fs.String("cmd", "", "")
	dotenvEnv := fs.String("dotenv-env", "", "")
	var installLauncher setupOptionalBool
	var addToPath setupOptionalBool
	var envMappings mappingFlag
	var fileMappings mappingFlag
	var dotenvMappings mappingFlag
	fs.Var(&installLauncher, "install", "always|never|ask")
	fs.Var(&addToPath, "add-to-path", "always|never|ask")
	fs.Var(&envMappings, "env", "")
	fs.Var(&fileMappings, "file", "")
	fs.Var(&dotenvMappings, "dotenv", "")
	if err := fs.Parse(normalizeAppConnectArgs(remaining)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp app connect <name> --cmd <command> [--project-root <path>] [--env APP_ENV=@REF] [--file APP_ENV=@REF] [--dotenv KEY=@REF --dotenv-env APP_ENV] [--install]")
	}
	if expandedRoot, expandErr := expandUserPath(strings.TrimSpace(*projectRoot)); expandErr != nil {
		return fmt.Errorf("--project-root: %w", expandErr)
	} else {
		*projectRoot = expandedRoot
	}
	if !*jsonOutput && !globalFlagsFromContext(ctx).json {
		warnBareEnvRefs(ctx, stderr, envMappings, "app connect", "--env")
		warnBareEnvRefs(ctx, stderr, fileMappings, "app connect", "--file")
		warnBareEnvRefs(ctx, stderr, dotenvMappings, "app connect", "--dotenv")
	}

	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	cfg := appConnectConfig{
		Name:            strings.TrimSpace(name),
		Command:         strings.TrimSpace(*command),
		DotenvEnv:       strings.TrimSpace(*dotenvEnv),
		InstallLauncher: installLauncher,
		AddToPath:       addToPath,
		EnvMappings:     envMappings,
		FileMappings:    fileMappings,
		DotenvMappings:  dotenvMappings,
	}
	if file, ok := ttyutil.StdinFile(stdin); ok && secretIsCharDeviceFn(file) {
		if err := appConnectPromptMissing(newSetupPrompter(stdin, stdout), &cfg); err != nil {
			return err
		}
	}
	if strings.TrimSpace(cfg.Name) == "" {
		return errors.New("usage: hasp app connect <name> --cmd <command> [--project-root <path>] [--env APP_ENV=SECRET] [--file APP_ENV=SECRET] [--dotenv KEY=SECRET --dotenv-env APP_ENV] [--install]")
	}
	if strings.TrimSpace(cfg.Command) == "" {
		return errors.New("app connect requires --cmd")
	}
	if err := validateAppConsumerName(cfg.Name); err != nil {
		return err
	}
	if len(cfg.DotenvMappings) > 0 && strings.TrimSpace(cfg.DotenvEnv) == "" {
		return errors.New("app connect requires --dotenv-env when --dotenv is used")
	}
	root := ""
	if strings.TrimSpace(*projectRoot) != "" {
		root, _, err = secretProjectContext(ctx, *projectRoot)
		if err != nil {
			return err
		}
		if _, _, _, err := ensureProjectBindingExplicit(ctx, handle, root); err != nil {
			return err
		}
	}
	cfg.ProjectRoot = root
	consumer, pathUpdate, err := connectAppConsumerWithHandle(ctx, handle, cfg, stdin, stdout, stderr)
	if err != nil {
		return err
	}
	appendAudit(audit.EventRun, "user", map[string]any{
		"action":        "consumer.app.connect",
		"consumer_type": "app",
		"consumer_name": consumer.Name,
		"project_root":  consumer.ProjectRoot,
		"launcher_path": consumer.LauncherPath,
		"path_updated":  pathUpdate.Changed,
		"shell_config":  pathUpdate.ConfigPath,
		"binding_count": len(consumer.Bindings),
		"outcome":       "connected",
	})
	payload := map[string]any{"consumer": consumer, "path_update": pathUpdate}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderAppConsumerSummary(w, "App connected", "Saved the app configuration.", consumer, pathUpdate)
	})
}

func connectAppConsumerWithHandle(ctx context.Context, handle *store.Handle, cfg appConnectConfig, stdin io.Reader, stdout io.Writer, stderr io.Writer) (store.AppConsumer, appPathUpdateResult, error) {
	bindings, err := appConsumerBindings(handle, cfg.EnvMappings, cfg.FileMappings, cfg.DotenvMappings)
	if err != nil {
		return store.AppConsumer{}, appPathUpdateResult{}, err
	}
	existingConsumer, existingErr := storeGetAppFn(handle, cfg.Name)
	hadExisting := existingErr == nil
	if existingErr != nil && !errors.Is(existingErr, store.ErrConsumerNotFound) {
		return store.AppConsumer{}, appPathUpdateResult{}, existingErr
	}
	consumer := store.AppConsumer{
		Name:        cfg.Name,
		ProjectRoot: cfg.ProjectRoot,
		Command:     []string{"sh", "-lc", appCommandString(cfg.Command), "hasp-app"},
		Bindings:    bindings,
		DotenvEnv:   cfg.DotenvEnv,
	}
	if hadExisting {
		consumer.LauncherPath = existingConsumer.LauncherPath
	}
	installChoice, err := resolveAppLauncherInstallChoice(ctx, cfg.Name, cfg.InstallLauncher, stdin, stdout, stderr)
	if err != nil {
		return store.AppConsumer{}, appPathUpdateResult{}, err
	}
	var launcherPlan appLauncherPlan
	if installChoice {
		launcherPlan, err = planAppLauncher(consumer.Name)
		if err != nil {
			return store.AppConsumer{}, appPathUpdateResult{}, err
		}
		consumer.LauncherPath = launcherPlan.Path
	}
	consumer, err = storeUpsertAppFn(handle, consumer)
	if err != nil {
		return store.AppConsumer{}, appPathUpdateResult{}, err
	}
	if installChoice {
		if err := writePlannedAppLauncher(launcherPlan); err != nil {
			if rollbackErr := rollbackAppConsumer(handle, hadExisting, existingConsumer, consumer.Name); rollbackErr != nil {
				return store.AppConsumer{}, appPathUpdateResult{}, fmt.Errorf("%w (rollback failed: %v)", err, rollbackErr)
			}
			return store.AppConsumer{}, appPathUpdateResult{}, err
		}
	}
	pathUpdate := appPathUpdateResult{}
	if installChoice {
		pathUpdate, err = ensureLauncherDirOnPathChoice(ctx, cfg.AddToPath, stdin, stdout, stderr, filepath.Dir(launcherPlan.Path))
		if err != nil {
			if rollbackErr := rollbackAppConsumer(handle, hadExisting, existingConsumer, consumer.Name); rollbackErr != nil {
				return store.AppConsumer{}, appPathUpdateResult{}, fmt.Errorf("%w (rollback failed: %v)", err, rollbackErr)
			}
			return store.AppConsumer{}, appPathUpdateResult{}, err
		}
	}
	return consumer, pathUpdate, nil
}

func appRunCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, s starter) error {
	name, remaining := consumerNameAndArgs(args)
	fs := flag.NewFlagSet("app run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" {
		return errors.New("usage: hasp app run <name> [args...]")
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	consumer, err := storeGetAppFn(handle, name)
	if err != nil {
		return err
	}
	command := append([]string{}, consumer.Command...)
	command = append(command, fs.Args()...)
	runResult, err := appExecuteConsumerFn(ctx, handle, consumer, command, stdout, stderr, s, "run", defaultExecDeps())
	if err != nil {
		return err
	}
	if runResult.ExitCode != 0 {
		return fmt.Errorf("command exited with code %d", runResult.ExitCode)
	}
	return nil
}

func appShellCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, s starter) error {
	name, remaining := consumerNameAndArgs(args)
	fs := flag.NewFlagSet("app shell", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" {
		return errors.New("usage: hasp app shell <name> [shell args...]")
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	consumer, err := storeGetAppFn(handle, name)
	if err != nil {
		return err
	}
	shell := strings.TrimSpace(appUserShellFn())
	if shell == "" {
		shell = "/bin/sh"
	}
	command := []string{shell, "-l"}
	command = append(command, fs.Args()...)
	runResult, err := appExecuteConsumerFn(ctx, handle, consumer, command, stdout, stderr, s, "shell", defaultExecDeps())
	if err != nil {
		return err
	}
	if runResult.ExitCode != 0 {
		return fmt.Errorf("command exited with code %d", runResult.ExitCode)
	}
	return nil
}

func appInstallCommand(ctx context.Context, args []string, stdout io.Writer) error {
	return appInstallCommandWithInput(ctx, args, nil, stdout, io.Discard)
}

func appInstallCommandWithInput(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	name, remaining := consumerNameAndArgs(args)
	fs := flag.NewFlagSet("app install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	var addToPath setupOptionalBool
	fs.Var(&addToPath, "add-to-path", "always|never|ask")
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		return errors.New("usage: hasp app install <name> [--add-to-path=always|never|ask]")
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	consumer, err := storeGetAppFn(handle, name)
	if err != nil {
		return err
	}
	launcherPlan, err := planAppLauncher(consumer.Name)
	if err != nil {
		return err
	}
	oldConsumer := consumer
	consumer.LauncherPath = launcherPlan.Path
	consumer, err = storeUpsertAppFn(handle, consumer)
	if err != nil {
		return err
	}
	if err := writePlannedAppLauncher(launcherPlan); err != nil {
		if _, rollbackErr := storeUpsertAppFn(handle, oldConsumer); rollbackErr != nil {
			return fmt.Errorf("%w (rollback failed: %v)", err, rollbackErr)
		}
		return err
	}
	pathUpdate, err := ensureLauncherDirOnPathChoice(ctx, addToPath, stdin, stdout, stderr, filepath.Dir(launcherPlan.Path))
	if err != nil {
		if _, rollbackErr := storeUpsertAppFn(handle, oldConsumer); rollbackErr != nil {
			return fmt.Errorf("%w (rollback failed: %v)", err, rollbackErr)
		}
		return err
	}
	appendAudit(audit.EventRun, "user", map[string]any{
		"action":        "consumer.app.install",
		"consumer_type": "app",
		"consumer_name": consumer.Name,
		"launcher_path": launcherPlan.Path,
		"path_updated":  pathUpdate.Changed,
		"shell_config":  pathUpdate.ConfigPath,
		"outcome":       "installed",
	})
	payload := map[string]any{"consumer": consumer, "path_update": pathUpdate}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderAppConsumerSummary(w, "App installed", "Installed or refreshed the launcher for the app.", consumer, pathUpdate)
	})
}

func appDisconnectCommand(ctx context.Context, args []string, stdout io.Writer) error {
	name, remaining := consumerNameAndArgs(args)
	fs := flag.NewFlagSet("app disconnect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		return errors.New("usage: hasp app disconnect <name>")
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	consumer, err := storeGetAppFn(handle, name)
	if err != nil {
		return err
	}
	if err := storeDeleteAppFn(handle, consumer.Name); err != nil {
		return err
	}
	if strings.TrimSpace(consumer.LauncherPath) != "" {
		if err := appRemoveFn(consumer.LauncherPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			if _, rollbackErr := storeUpsertAppFn(handle, consumer); rollbackErr != nil {
				return fmt.Errorf("%w (rollback failed: %v)", err, rollbackErr)
			}
			return err
		}
	}
	appendAudit(audit.EventRun, "user", map[string]any{
		"action":        "consumer.app.disconnect",
		"consumer_type": "app",
		"consumer_name": consumer.Name,
		"launcher_path": consumer.LauncherPath,
		"outcome":       "disconnected",
	})
	payload := map[string]any{"consumer_name": consumer.Name, "outcome": "disconnected"}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSimpleAction(ctx, w, "App disconnected", "Removed the saved app.",
			cliPair("Name", consumer.Name),
			cliPair("Outcome", "disconnected"),
		)
	})
}

func appListCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("app list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	consumers := storeListAppsFn(handle)
	payload := map[string]any{"consumers": consumers}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderAppConsumerList(w, consumers)
	})
}

func consumerNameAndArgs(args []string) (string, []string) {
	if len(args) == 0 {
		return "", args
	}
	if strings.HasPrefix(strings.TrimSpace(args[0]), "-") {
		return "", args
	}
	return strings.TrimSpace(args[0]), args[1:]
}

func appConsumerBindings(handle *store.Handle, envMappings mappingFlag, fileMappings mappingFlag, dotenvMappings mappingFlag) ([]store.AppBinding, error) {
	out := make([]store.AppBinding, 0, len(envMappings)+len(fileMappings)+len(dotenvMappings))
	for target, secretName := range envMappings {
		item, err := secretGetItemFn(handle, secretName)
		if err != nil {
			return nil, err
		}
		if item.Kind != store.ItemKindKV {
			return nil, fmt.Errorf("env delivery requires kv secret %q", secretName)
		}
		out = append(out, store.AppBinding{SecretName: secretName, Delivery: store.AppDeliveryEnv, Target: target})
	}
	for target, secretName := range fileMappings {
		if _, err := secretGetItemFn(handle, secretName); err != nil {
			return nil, err
		}
		out = append(out, store.AppBinding{SecretName: secretName, Delivery: store.AppDeliveryTempFile, Target: target})
	}
	for target, secretName := range dotenvMappings {
		item, err := secretGetItemFn(handle, secretName)
		if err != nil {
			return nil, err
		}
		if item.Kind != store.ItemKindKV {
			return nil, fmt.Errorf("temp dotenv delivery requires kv secret %q", secretName)
		}
		out = append(out, store.AppBinding{SecretName: secretName, Delivery: store.AppDeliveryTempDotenv, Target: target})
	}
	return out, nil
}

func executeAppConsumer(ctx context.Context, handle *store.Handle, consumer store.AppConsumer, command []string, stdout io.Writer, stderr io.Writer, s starter, action string, deps execDeps) (runner.Result, error) {
	env := map[string]string{}
	files := map[string][]byte{}
	dotenvLines := make([]string, 0)
	items := make([]store.Item, 0, len(consumer.Bindings))
	bindingID := ""
	sessionToken := ""
	if strings.TrimSpace(consumer.ProjectRoot) != "" {
		session, err := ensureSessionAppFn(ctx, s, consumer.ProjectRoot, "", "app:"+consumer.Name)
		if err != nil {
			return runner.Result{}, err
		}
		binding, _, _, err := ensureProjectBinding(ctx, handle, consumer.ProjectRoot)
		if err != nil {
			return runner.Result{}, err
		}
		if err := requireProjectBinding(binding, consumer.ProjectRoot); err != nil {
			return runner.Result{}, err
		}
		bindingID = binding.ID
		sessionToken = session.Token
	}
	for _, bindingSpec := range consumer.Bindings {
		item, err := secretGetItemFn(handle, bindingSpec.SecretName)
		if err != nil {
			return runner.Result{}, err
		}
		if bindingID != "" {
			item, err = deps.AuthorizeItem(handle, bindingID, sessionToken, item, store.OperationRun, store.GrantWindow, store.GrantSession, 15*time.Minute)
			if err != nil {
				return runner.Result{}, err
			}
		}
		items = append(items, item)
		switch bindingSpec.Delivery {
		case store.AppDeliveryEnv:
			env[bindingSpec.Target] = string(item.Value)
		case store.AppDeliveryTempFile:
			files[bindingSpec.Target] = item.Value
		case store.AppDeliveryTempDotenv:
			dotenvLines = append(dotenvLines, bindingSpec.Target+"="+string(item.Value))
		default:
			return runner.Result{}, fmt.Errorf("unsupported app delivery %q", bindingSpec.Delivery)
		}
	}
	if len(dotenvLines) > 0 {
		if strings.TrimSpace(consumer.DotenvEnv) == "" {
			return runner.Result{}, errors.New("app dotenv delivery requires dotenv_env")
		}
		files[consumer.DotenvEnv] = []byte(strings.Join(dotenvLines, "\n") + "\n")
	}

	result, err := deps.RunnerExecute(ctx, runner.Input{
		ProjectRoot: consumer.ProjectRoot,
		Command:     command,
		Env:         env,
		Files:       files,
	})
	if err != nil {
		return runner.Result{}, err
	}
	stdoutResult := redactor.Apply(result.Stdout, items)
	stderrResult := redactor.Apply(result.Stderr, items)
	if len(stdoutResult.Output) > 0 {
		if _, err := stdout.Write(stdoutResult.Output); err != nil {
			return runner.Result{}, err
		}
	}
	if len(stderrResult.Output) > 0 {
		if _, err := stderr.Write(stderrResult.Output); err != nil {
			return runner.Result{}, err
		}
	}
	appendAudit(audit.EventRun, "user", map[string]any{
		"action":         "consumer.app." + action,
		"consumer_type":  "app",
		"consumer_name":  consumer.Name,
		"project_root":   consumer.ProjectRoot,
		"command":        command,
		"env_names":      sortedStringKeys(env),
		"file_env_names": sortedByteMapKeys(files),
		"secret_refs":    appConsumerSecretRefs(consumer),
		"exit_code":      result.ExitCode,
		"outcome":        fmt.Sprintf("exit_%d", result.ExitCode),
	})
	return result, nil
}

type appLauncherPlan struct {
	Path    string
	Content []byte
}

type appConnectConfig struct {
	Name            string
	ProjectRoot     string
	Command         string
	DotenvEnv       string
	InstallLauncher setupOptionalBool
	AddToPath       setupOptionalBool
	EnvMappings     mappingFlag
	FileMappings    mappingFlag
	DotenvMappings  mappingFlag
}

func installAppLauncher(name string) (string, error) {
	plan, err := planAppLauncher(name)
	if err != nil {
		return "", err
	}
	if err := writePlannedAppLauncher(plan); err != nil {
		return "", err
	}
	return plan.Path, nil
}

func planAppLauncher(name string) (appLauncherPlan, error) {
	if err := validateAppConsumerName(name); err != nil {
		return appLauncherPlan{}, err
	}
	resolved, err := appResolvePathsFn()
	if err != nil {
		return appLauncherPlan{}, err
	}
	binDir := filepath.Join(resolved.HomeDir, "bin")
	launcherPath := filepath.Join(binDir, name)
	content := []byte("#!/usr/bin/env bash\n# hasp-managed launcher\nset -euo pipefail\nexport HASP_HOME=" + strconvQuote(resolved.HomeDir) + "\nexec " + strconvQuote(setupHaspCommandPath()) + " app run " + strconvQuote(name) + " \"$@\"\n")
	existing, err := appReadFileFn(launcherPath)
	if err == nil {
		if !bytes.Contains(existing, []byte("# hasp-managed launcher")) {
			return appLauncherPlan{}, fmt.Errorf("launcher path %q already exists and is not managed by hasp", launcherPath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return appLauncherPlan{}, err
	}
	return appLauncherPlan{Path: launcherPath, Content: content}, nil
}

func writePlannedAppLauncher(plan appLauncherPlan) error {
	if err := appMkdirAllFn(filepath.Dir(plan.Path), 0o700); err != nil {
		return err
	}
	return appWriteFileFn(plan.Path, plan.Content, 0o700)
}

func rollbackAppConsumer(handle *store.Handle, hadExisting bool, existing store.AppConsumer, name string) error {
	if hadExisting {
		_, err := storeUpsertAppFn(handle, existing)
		return err
	}
	return storeDeleteAppFn(handle, name)
}

func resolveAppLauncherInstallChoice(ctx context.Context, name string, explicit setupOptionalBool, stdin io.Reader, stdout io.Writer, stderr io.Writer) (bool, error) {
	if explicit.set {
		return explicit.value, nil
	}
	if globalFlagsFromContext(ctx).yes {
		return false, nil
	}
	file, ok := ttyutil.StdinFile(stdin)
	if !ok || !secretIsCharDeviceFn(file) {
		return false, nil
	}
	prompt := newSecretPrompt(stdin, stdout, stderr)
	return prompt.confirm(fmt.Sprintf("Install launcher command %q", name), false)
}

func normalizeAppConnectArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "--install" {
			out = append(out, "--install=always")
			continue
		}
		out = append(out, arg)
	}
	return out
}

func appConnectPromptMissing(prompt *setupPrompter, cfg *appConnectConfig) error {
	if strings.TrimSpace(cfg.Name) == "" {
		value, err := promptString(prompt, "App name", "")
		if err != nil {
			return err
		}
		cfg.Name = strings.TrimSpace(value)
	}
	if strings.TrimSpace(cfg.Command) == "" {
		value, err := promptString(prompt, "Command used to start this app", "")
		if err != nil {
			return err
		}
		cfg.Command = strings.TrimSpace(value)
	}
	if len(cfg.EnvMappings)+len(cfg.FileMappings)+len(cfg.DotenvMappings) == 0 {
		addMapping, err := promptBool(prompt, "Add a secret mapping now", true)
		if err != nil {
			return err
		}
		for addMapping {
			secretName, err := promptString(prompt, "Vault secret name", "")
			if err != nil {
				return err
			}
			delivery, err := promptString(prompt, "Delivery mode (env/file/dotenv)", "env")
			if err != nil {
				return err
			}
			switch strings.TrimSpace(strings.ToLower(delivery)) {
			case "env":
				target, err := promptString(prompt, "Environment variable to set", secretName)
				if err != nil {
					return err
				}
				if cfg.EnvMappings == nil {
					cfg.EnvMappings = mappingFlag{}
				}
				cfg.EnvMappings[strings.TrimSpace(target)] = strings.TrimSpace(secretName)
			case "file":
				target, err := promptString(prompt, "Environment variable that should point to the temp file", secretName+"_PATH")
				if err != nil {
					return err
				}
				if cfg.FileMappings == nil {
					cfg.FileMappings = mappingFlag{}
				}
				cfg.FileMappings[strings.TrimSpace(target)] = strings.TrimSpace(secretName)
			case "dotenv":
				target, err := promptString(prompt, "Key name inside the dotenv file", secretName)
				if err != nil {
					return err
				}
				if cfg.DotenvMappings == nil {
					cfg.DotenvMappings = mappingFlag{}
				}
				cfg.DotenvMappings[strings.TrimSpace(target)] = strings.TrimSpace(secretName)
				if strings.TrimSpace(cfg.DotenvEnv) == "" {
					dotenvEnv, err := promptString(prompt, "Environment variable that should point to the temp dotenv file", "HASP_DOTENV_FILE")
					if err != nil {
						return err
					}
					cfg.DotenvEnv = strings.TrimSpace(dotenvEnv)
				}
			default:
				return fmt.Errorf("unsupported delivery mode %q", delivery)
			}
			addMapping, err = promptBool(prompt, "Add another secret mapping", false)
			if err != nil {
				return err
			}
		}
	} else if len(cfg.DotenvMappings) > 0 && strings.TrimSpace(cfg.DotenvEnv) == "" {
		value, err := promptString(prompt, "Environment variable that should point to the temp dotenv file", "HASP_DOTENV_FILE")
		if err != nil {
			return err
		}
		cfg.DotenvEnv = strings.TrimSpace(value)
	}
	return nil
}

func appCommandString(command string) string {
	return "exec " + command + ` "$@"`
}

func validateAppConsumerName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("app name is required")
	}
	if name == "." || name == ".." {
		return fmt.Errorf("invalid app name %q", name)
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("invalid app name %q", name)
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '-', '_', '.':
			continue
		default:
			return fmt.Errorf("invalid app name %q", name)
		}
	}
	return nil
}

func appConsumerSecretRefs(consumer store.AppConsumer) []string {
	refs := make([]string, 0, len(consumer.Bindings))
	for _, binding := range consumer.Bindings {
		refs = append(refs, "@"+binding.SecretName)
	}
	slices.Sort(refs)
	return refs
}

func sortedStringKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func sortedByteMapKeys(values map[string][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
