package runtimeops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

func tuiHandler(ctx context.Context, deps Deps, args []string, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", ".", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if stderr != nil {
		fmt.Fprintln(stderr, "warning: `hasp tui` is deprecated and prints a one-shot snapshot, not an interactive UI; use `hasp project status` for the structured project view.") //nolint:errcheck
	}

	if deps.ExpandUserPath != nil {
		expanded, err := deps.ExpandUserPath(strings.TrimSpace(*projectRoot))
		if err != nil {
			return fmt.Errorf("--project-root: %w", err)
		}
		*projectRoot = expanded
	}

	if deps.OpenVault == nil {
		return errors.New("runtimeops: OpenVault not configured")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}

	if deps.EnsureProjectBinding == nil {
		return errors.New("runtimeops: EnsureProjectBinding not configured")
	}
	binding, visible, _, err := deps.EnsureProjectBinding(ctx, handle, *projectRoot)
	if err != nil {
		return err
	}

	jsonOut := *jsonOutput || globalJSON(ctx, deps)
	if jsonOut {
		payload := map[string]any{
			"binding":       binding,
			"visible":       visible,
			"vault_items":   len(handle.ListItems()),
			"project_root":  binding.CanonicalRoot,
			"visible_count": len(visible),
		}
		if deps.WriteJSONResponse != nil {
			return deps.WriteJSONResponse(stdout, payload)
		}
		// Fallback: minimal JSON
		_, err := fmt.Fprintf(stdout, `{"binding_id":%q,"visible_count":%d}`+"\n", binding.ID, len(visible))
		return err
	}

	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "HASP TUI\tproject=%s\n", binding.CanonicalRoot)
	fmt.Fprintf(tw, "binding_id\t%s\n", binding.ID)
	fmt.Fprintf(tw, "visible_refs\t%d\n", len(visible))
	items := handle.ListItems()
	fmt.Fprintf(tw, "vault_items\t%d\n", len(items))
	for _, ref := range visible {
		fmt.Fprintf(tw, "ref\t%s\t%s\t%s\n", ref.Alias, ref.Kind, ref.PolicyLevel)
	}
	return tw.Flush()
}
