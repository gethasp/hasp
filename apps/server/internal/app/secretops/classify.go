package secretops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func secretClassifyCommand(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := newFlagSet(deps, "secret classify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	classification := fs.String("classification", "", "")
	if err := fs.Parse(reorderFlagsBeforePositionals(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hasp secret classify NAME --classification confidential|configuration [--json]")
	}
	if *classification != string(store.ClassificationConfidential) && *classification != string(store.ClassificationConfiguration) {
		return errors.New("--classification must be confidential or configuration")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	name := strings.TrimPrefix(fs.Arg(0), "@")
	if deps.EnforceClassificationChange == nil {
		return errors.New("classification operator check is unavailable")
	}
	if err := deps.EnforceClassificationChange(ctx, handle, name); err != nil {
		return err
	}
	item, err := handle.SetItemClassification(name, store.ItemClassification(*classification))
	if err != nil {
		return err
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, map[string]any{"name": item.Name, "classification": item.EffectiveClassification()}, func(out io.Writer) error {
		_, err := fmt.Fprintf(out, "%s: %s\n", item.Name, item.EffectiveClassification())
		return err
	})
}
