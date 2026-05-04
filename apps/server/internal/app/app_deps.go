package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gethasp/hasp/apps/server/internal/app/appops"
	"github.com/gethasp/hasp/apps/server/internal/app/ttyutil"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// defaultAppDeps builds an appops.Deps wired to the package-level seam
// vars. Each closure reads the current value of its seam var at call time, so
// test overrides of storeGetAppFn, appExecuteConsumerFn, etc. propagate
// transparently through the appops handlers.
func defaultAppDeps() appops.Deps {
	return appops.Deps{
		// ── The 14 named seams pinned by the contract test ────────────────────

		AppResolvePaths: func() (string, error) {
			resolved, err := appResolvePathsFn()
			if err != nil {
				return "", err
			}
			return resolved.HomeDir, nil
		},
		AppWriteFile: func(path string, data []byte, perm os.FileMode) error {
			return appWriteFileFn(path, data, perm)
		},
		AppReadFile: func(path string) ([]byte, error) {
			return appReadFileFn(path)
		},
		AppMkdirAll: func(path string, perm os.FileMode) error {
			return appMkdirAllFn(path, perm)
		},
		AppRemove: func(path string) error {
			return appRemoveFn(path)
		},
		AppUserShell: func() string {
			return appUserShellFn()
		},
		AppCurrentShell: func() string {
			return appCurrentShellFn()
		},
		AppUserHomeDir: func() (string, error) {
			return appUserHomeDirFn()
		},
		StoreGetApp: func(handle *store.Handle, name string) (store.AppConsumer, error) {
			return storeGetAppFn(handle, name)
		},
		StoreListApps: func(handle *store.Handle) []store.AppConsumer {
			return storeListAppsFn(handle)
		},
		StoreUpsertApp: func(handle *store.Handle, consumer store.AppConsumer) (store.AppConsumer, error) {
			return storeUpsertAppFn(handle, consumer)
		},
		StoreDeleteApp: func(handle *store.Handle, name string) error {
			return storeDeleteAppFn(handle, name)
		},
		AppExecuteConsumer: func(ctx context.Context, handle *store.Handle, consumer store.AppConsumer, command []string, stdout, stderr io.Writer, s appops.Starter, action string) (runner.Result, error) {
			// s was constructed by AppNewStarter which calls newRuntimeStarterFn()
			// returning *runtimeStarter — it implements both appops.Starter and
			// the package-private starter interface.
			var priv starter
			if s != nil {
				priv = s.(starter)
			}
			return appExecuteConsumerFn(ctx, handle, consumer, command, stdout, stderr, priv, action, defaultExecDeps())
		},
		AppInstallLauncher: func(name string) (string, error) {
			return appInstallLauncherFn(name)
		},

		// ── Additional deps ───────────────────────────────────────────────────

		AppNewStarter: func() (appops.Starter, error) {
			// *runtimeStarter satisfies appops.Starter via structural typing.
			return newRuntimeStarterFn()
		},

		OpenVault: func(ctx context.Context) (*store.Handle, error) {
			return openVaultHandleFn(ctx)
		},

		AppendAudit: func(eventType string, actor string, details map[string]any) {
			appendAudit(eventType, actor, details)
		},

		RenderJSONOrHuman: renderJSONOrHuman,

		RenderConnectResult: func(out io.Writer, consumer store.AppConsumer, pathUpdate appops.AppPathUpdate) error {
			return renderAppConsumerSummary(out, "App connected", "Saved the app configuration.", consumer, appPathUpdateResult{
				ConfigPath: pathUpdate.ConfigPath,
				Changed:    pathUpdate.Changed,
			})
		},

		RenderInstallResult: func(out io.Writer, consumer store.AppConsumer, pathUpdate appops.AppPathUpdate) error {
			return renderAppConsumerSummary(out, "App installed", "Installed or refreshed the launcher for the app.", consumer, appPathUpdateResult{
				ConfigPath: pathUpdate.ConfigPath,
				Changed:    pathUpdate.Changed,
			})
		},

		RenderConsumerList: renderAppConsumerList,

		RenderSimpleAction: renderSimpleAction,

		IsHelpArg:      isHelpArg,
		PrintHelpTopic: printHelpTopic,
		NewFlagSet:     nil, // use appops default (flag.NewFlagSet)

		ExpandUserPath: expandUserPath,

		ResolveProjectRoot: secretProjectContext,

		EnsureProjectBinding: func(ctx context.Context, handle *store.Handle, root string) error {
			_, _, _, err := ensureProjectBindingExplicit(ctx, handle, root)
			return err
		},

		GlobalJSON: func(ctx context.Context) bool {
			return globalFlagsFromContext(ctx).json
		},

		WarnBareEnvRefs: func(ctx context.Context, stderr io.Writer, mappings map[string]string, cmd string, flag string) {
			warnBareEnvRefs(ctx, stderr, mappingFlag(mappings), cmd, flag)
		},

		StdinIsCharDevice: func(stdin io.Reader) bool {
			file, ok := ttyutil.StdinFile(stdin)
			if !ok {
				return false
			}
			return secretIsCharDeviceFn(file)
		},

		PromptConnectMissing: func(stdin io.Reader, stdout io.Writer, cfg *appops.AppConnectConfig) error {
			private := &appConnectConfig{
				Name:            cfg.Name,
				Command:         cfg.Command,
				Target:          cfg.Target,
				DotenvEnv:       cfg.DotenvEnv,
				InstallLauncher: setupOptionalBool{set: cfg.InstallLauncher.Set, value: cfg.InstallLauncher.Value},
				AddToPath:       setupOptionalBool{set: cfg.AddToPath.Set, value: cfg.AddToPath.Value},
				EnvMappings:     mappingFlag(cfg.EnvMappings),
				FileMappings:    mappingFlag(cfg.FileMappings),
				DotenvMappings:  mappingFlag(cfg.DotenvMappings),
			}
			if err := appConnectPromptMissing(newSetupPrompter(stdin, stdout), private); err != nil {
				return err
			}
			// Copy results back.
			cfg.Name = private.Name
			cfg.Command = private.Command
			cfg.Target = private.Target
			cfg.DotenvEnv = private.DotenvEnv
			cfg.InstallLauncher = appops.OptionalBool{Set: private.InstallLauncher.set, Value: private.InstallLauncher.value}
			cfg.AddToPath = appops.OptionalBool{Set: private.AddToPath.set, Value: private.AddToPath.value}
			cfg.EnvMappings = map[string]string(private.EnvMappings)
			cfg.FileMappings = map[string]string(private.FileMappings)
			cfg.DotenvMappings = map[string]string(private.DotenvMappings)
			return nil
		},

		ValidateAppConsumerName: validateAppConsumerName,

		NormalizeConnectArgs: normalizeAppConnectArgs,

		ConnectConsumer: func(ctx context.Context, handle *store.Handle, cfg appops.AppConnectConfig, stdin io.Reader, stdout, stderr io.Writer) (store.AppConsumer, appops.AppPathUpdate, error) {
			private := appConnectConfig{
				Name:            cfg.Name,
				ProjectRoot:     cfg.ProjectRoot,
				Target:          cfg.Target,
				Command:         cfg.Command,
				DotenvEnv:       cfg.DotenvEnv,
				InstallLauncher: setupOptionalBool{set: cfg.InstallLauncher.Set, value: cfg.InstallLauncher.Value},
				AddToPath:       setupOptionalBool{set: cfg.AddToPath.Set, value: cfg.AddToPath.Value},
				EnvMappings:     mappingFlag(cfg.EnvMappings),
				FileMappings:    mappingFlag(cfg.FileMappings),
				DotenvMappings:  mappingFlag(cfg.DotenvMappings),
			}
			consumer, result, err := connectAppConsumerWithHandle(ctx, handle, private, stdin, stdout, stderr)
			if err != nil {
				return store.AppConsumer{}, appops.AppPathUpdate{}, err
			}
			return consumer, appops.AppPathUpdate{
				ConfigPath: result.ConfigPath,
				Changed:    result.Changed,
			}, nil
		},

		InstallConsumer: func(ctx context.Context, handle *store.Handle, name string, addToPath appops.OptionalBool, stdin io.Reader, stdout, stderr io.Writer) (store.AppConsumer, appops.AppPathUpdate, error) {
			consumer, err := storeGetAppFn(handle, name)
			if err != nil {
				return store.AppConsumer{}, appops.AppPathUpdate{}, err
			}
			launcherPlan, err := planAppLauncher(consumer.Name)
			if err != nil {
				return store.AppConsumer{}, appops.AppPathUpdate{}, err
			}
			oldConsumer := consumer
			consumer.LauncherPath = launcherPlan.Path
			consumer, err = storeUpsertAppFn(handle, consumer)
			if err != nil {
				return store.AppConsumer{}, appops.AppPathUpdate{}, err
			}
			if err := writePlannedAppLauncher(launcherPlan); err != nil {
				if _, rollbackErr := storeUpsertAppFn(handle, oldConsumer); rollbackErr != nil {
					return store.AppConsumer{}, appops.AppPathUpdate{}, fmt.Errorf("%w (rollback failed: %v)", err, rollbackErr)
				}
				return store.AppConsumer{}, appops.AppPathUpdate{}, err
			}
			addToPathPrivate := setupOptionalBool{set: addToPath.Set, value: addToPath.Value}
			pathUpdate, err := ensureLauncherDirOnPathChoice(ctx, addToPathPrivate, stdin, stdout, stderr, filepath.Dir(launcherPlan.Path))
			if err != nil {
				if _, rollbackErr := storeUpsertAppFn(handle, oldConsumer); rollbackErr != nil {
					return store.AppConsumer{}, appops.AppPathUpdate{}, fmt.Errorf("%w (rollback failed: %v)", err, rollbackErr)
				}
				return store.AppConsumer{}, appops.AppPathUpdate{}, err
			}
			return consumer, appops.AppPathUpdate{
				ConfigPath: pathUpdate.ConfigPath,
				Changed:    pathUpdate.Changed,
			}, nil
		},
	}
}
