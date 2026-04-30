package appops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

func appConnectHandler(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	name, remaining := consumerNameAndArgs(args)
	fs := newFlagSet(deps, "app connect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", "", "")
	target := fs.String("target", "", "")
	command := fs.String("cmd", "", "")
	dotenvEnv := fs.String("dotenv-env", "", "")
	var installLauncher OptionalBool
	var addToPath OptionalBool
	var envMappings map[string]string
	var fileMappings map[string]string
	var dotenvMappings map[string]string
	fs.Var(newOptionalBoolFlag(&installLauncher), "install", "always|never|ask")
	fs.Var(newOptionalBoolFlag(&addToPath), "add-to-path", "always|never|ask")
	fs.Var(newStringMapFlag(&envMappings), "env", "")
	fs.Var(newStringMapFlag(&fileMappings), "file", "")
	fs.Var(newStringMapFlag(&dotenvMappings), "dotenv", "")

	var normalizeArgs []string
	if deps.NormalizeConnectArgs != nil {
		normalizeArgs = deps.NormalizeConnectArgs(remaining)
	} else {
		normalizeArgs = defaultNormalizeConnectArgs(remaining)
	}
	if err := fs.Parse(normalizeArgs); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp app connect <name> --cmd <command> [--project-root <path>] [--env APP_ENV=@REF] [--file APP_ENV=@REF] [--dotenv KEY=@REF --dotenv-env APP_ENV] [--install]")
	}

	globalJSON := false
	if deps.GlobalJSON != nil {
		globalJSON = deps.GlobalJSON(ctx)
	}
	if !*jsonOutput && !globalJSON && deps.WarnBareEnvRefs != nil {
		deps.WarnBareEnvRefs(ctx, stderr, envMappings, "app connect", "--env")
		deps.WarnBareEnvRefs(ctx, stderr, fileMappings, "app connect", "--file")
		deps.WarnBareEnvRefs(ctx, stderr, dotenvMappings, "app connect", "--dotenv")
	}

	if strings.TrimSpace(*target) != "" && strings.TrimSpace(*projectRoot) == "" {
		*projectRoot = "."
	}
	if strings.TrimSpace(*target) != "" && (len(envMappings) > 0 || len(fileMappings) > 0 || len(dotenvMappings) > 0) {
		return errors.New("--target cannot be combined with explicit app delivery mappings")
	}
	if deps.ExpandUserPath != nil && strings.TrimSpace(*projectRoot) != "" {
		if expandedRoot, expandErr := deps.ExpandUserPath(strings.TrimSpace(*projectRoot)); expandErr != nil {
			return fmt.Errorf("--project-root: %w", expandErr)
		} else {
			*projectRoot = expandedRoot
		}
	}

	cfg := AppConnectConfig{
		Name:            strings.TrimSpace(name),
		Target:          strings.TrimSpace(*target),
		Command:         strings.TrimSpace(*command),
		DotenvEnv:       strings.TrimSpace(*dotenvEnv),
		InstallLauncher: installLauncher,
		AddToPath:       addToPath,
		EnvMappings:     envMappings,
		FileMappings:    fileMappings,
		DotenvMappings:  dotenvMappings,
	}

	if deps.StdinIsCharDevice != nil && stdin != nil && deps.StdinIsCharDevice(stdin) {
		if deps.PromptConnectMissing != nil {
			if err := deps.PromptConnectMissing(stdin, stdout, &cfg); err != nil {
				return err
			}
		}
	}

	if strings.TrimSpace(cfg.Name) == "" {
		return errors.New("usage: hasp app connect <name> --cmd <command> [--project-root <path>] [--env APP_ENV=SECRET] [--file APP_ENV=SECRET] [--dotenv KEY=SECRET --dotenv-env APP_ENV] [--install]")
	}
	if strings.TrimSpace(cfg.Command) == "" && strings.TrimSpace(cfg.Target) == "" {
		return errors.New("app connect requires --cmd")
	}
	if deps.ValidateAppConsumerName != nil {
		if err := deps.ValidateAppConsumerName(cfg.Name); err != nil {
			return err
		}
	}
	if len(cfg.DotenvMappings) > 0 && strings.TrimSpace(cfg.DotenvEnv) == "" {
		return errors.New("app connect requires --dotenv-env when --dotenv is used")
	}

	if deps.OpenVault == nil {
		return errors.New("appops: OpenVault dep not wired")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}

	root := ""
	if strings.TrimSpace(*projectRoot) != "" {
		if deps.ResolveProjectRoot != nil {
			root, _, err = deps.ResolveProjectRoot(ctx, *projectRoot)
			if err != nil {
				return err
			}
		}
		if deps.EnsureProjectBinding != nil {
			if err := deps.EnsureProjectBinding(ctx, handle, root); err != nil {
				return err
			}
		}
	}
	cfg.ProjectRoot = root

	if deps.ConnectConsumer == nil {
		return errors.New("appops: ConnectConsumer dep not wired")
	}
	consumer, pathUpdate, err := deps.ConnectConsumer(ctx, handle, cfg, stdin, stdout, stderr)
	if err != nil {
		return err
	}

	if deps.AppendAudit != nil {
		deps.AppendAudit(audit.EventRun, "user", map[string]any{
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
	}
	payload := map[string]any{"consumer": consumer, "path_update": pathUpdate}
	if deps.RenderJSONOrHuman == nil {
		return nil
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		if deps.RenderConnectResult != nil {
			return deps.RenderConnectResult(w, consumer, pathUpdate)
		}
		return nil
	})
}

func appDisconnectHandler(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	name, remaining := consumerNameAndArgs(args)
	fs := newFlagSet(deps, "app disconnect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		return errors.New("usage: hasp app disconnect <name>")
	}
	if deps.OpenVault == nil {
		return errors.New("appops: OpenVault dep not wired")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	consumer, err := deps.StoreGetApp(handle, name)
	if err != nil {
		return err
	}
	if err := deps.StoreDeleteApp(handle, consumer.Name); err != nil {
		return err
	}
	if strings.TrimSpace(consumer.LauncherPath) != "" && deps.AppRemove != nil {
		if removeErr := deps.AppRemove(consumer.LauncherPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			if deps.StoreUpsertApp != nil {
				if _, rollbackErr := deps.StoreUpsertApp(handle, consumer); rollbackErr != nil {
					return fmt.Errorf("%w (rollback failed: %v)", removeErr, rollbackErr)
				}
			}
			return removeErr
		}
	}
	if deps.AppendAudit != nil {
		deps.AppendAudit(audit.EventRun, "user", map[string]any{
			"action":        "consumer.app.disconnect",
			"consumer_type": "app",
			"consumer_name": consumer.Name,
			"launcher_path": consumer.LauncherPath,
			"outcome":       "disconnected",
		})
	}
	payload := map[string]any{"consumer_name": consumer.Name, "outcome": "disconnected"}
	if deps.RenderJSONOrHuman == nil {
		return nil
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		if deps.RenderSimpleAction != nil {
			return deps.RenderSimpleAction(ctx, w, "App disconnected", "Removed the saved app.",
				cliPair("Name", consumer.Name),
				cliPair("Outcome", "disconnected"),
			)
		}
		return nil
	})
}

// defaultNormalizeConnectArgs normalises bare --install to --install=always.
func defaultNormalizeConnectArgs(args []string) []string {
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

// stringMapFlag implements flag.Value for map[string]string.
type stringMapFlag struct {
	m *map[string]string
}

func newStringMapFlag(m *map[string]string) *stringMapFlag {
	return &stringMapFlag{m: m}
}

func (f *stringMapFlag) String() string {
	if f.m == nil || *f.m == nil {
		return ""
	}
	parts := make([]string, 0, len(*f.m))
	for k, v := range *f.m {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

func (f *stringMapFlag) Set(value string) error {
	key, ref, ok := strings.Cut(value, "=")
	if !ok || strings.TrimSpace(key) == "" || strings.TrimSpace(ref) == "" {
		return fmt.Errorf("expected NAME=REFERENCE")
	}
	if *f.m == nil {
		*f.m = map[string]string{}
	}
	(*f.m)[strings.TrimSpace(key)] = strings.TrimSpace(ref)
	return nil
}

// optionalBoolFlag implements flag.Value for OptionalBool.
type optionalBoolFlag struct {
	b *OptionalBool
}

func newOptionalBoolFlag(b *OptionalBool) *optionalBoolFlag {
	return &optionalBoolFlag{b: b}
}

func (f *optionalBoolFlag) String() string {
	if f.b == nil || !f.b.Set {
		return ""
	}
	if f.b.Value {
		return "true"
	}
	return "false"
}

func (f *optionalBoolFlag) Set(value string) error {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "always", "true", "1", "yes", "y":
		f.b.Set = true
		f.b.Value = true
	case "never", "false", "0", "no", "n":
		f.b.Set = true
		f.b.Value = false
	default:
		return fmt.Errorf("invalid value %q; use always/never", value)
	}
	return nil
}
