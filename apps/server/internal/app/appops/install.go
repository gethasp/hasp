package appops

import (
	"context"
	"errors"
	"flag"
	"io"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

func appInstallHandler(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	name, remaining := consumerNameAndArgs(args)
	fs := newFlagSet(deps, "app install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	var addToPath OptionalBool
	fs.Var(newOptionalBoolFlag(&addToPath), "add-to-path", "always|never|ask")
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		return errors.New("usage: hasp app install <name> [--add-to-path=always|never|ask]")
	}
	if deps.OpenVault == nil {
		return errors.New("appops: OpenVault dep not wired")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	if deps.InstallConsumer == nil {
		return errors.New("appops: InstallConsumer dep not wired")
	}
	consumer, pathUpdate, err := deps.InstallConsumer(ctx, handle, name, addToPath, stdin, stdout, stderr)
	if err != nil {
		return err
	}
	if deps.AppendAudit != nil {
		deps.AppendAudit(audit.EventRun, "user", map[string]any{
			"action":        "consumer.app.install",
			"consumer_type": "app",
			"consumer_name": consumer.Name,
			"launcher_path": consumer.LauncherPath,
			"path_updated":  pathUpdate.Changed,
			"shell_config":  pathUpdate.ConfigPath,
			"outcome":       "installed",
		})
	}
	payload := map[string]any{"consumer": consumer, "path_update": pathUpdate}
	if deps.RenderJSONOrHuman == nil {
		return nil
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		if deps.RenderInstallResult != nil {
			return deps.RenderInstallResult(w, consumer, pathUpdate)
		}
		return nil
	})
}
