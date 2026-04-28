package sessionops

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func sessionOpen(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("session open", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	hostLabel := fs.String("host-label", "generic-client", "")
	projectRoot := fs.String("project-root", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Expand ~ in path if ExpandUserPath is wired.
	if deps.ExpandUserPath != nil {
		expanded, err := deps.ExpandUserPath(strings.TrimSpace(*projectRoot))
		if err != nil {
			return fmt.Errorf("--project-root: %w", err)
		}
		*projectRoot = expanded
	}

	canonicalRoot := *projectRoot
	if deps.CanonicalProjectRoot != nil {
		root, err := deps.CanonicalProjectRoot(ctx, *projectRoot)
		if err != nil {
			return err
		}
		canonicalRoot = root
	}

	if deps.OpenVault != nil {
		handle, err := deps.OpenVault(ctx)
		if err != nil {
			return err
		}
		if deps.EnsureProjectBinding != nil {
			if err := deps.EnsureProjectBinding(ctx, handle, canonicalRoot); err != nil {
				return err
			}
		}
	}

	if deps.NewStarter == nil {
		return fmt.Errorf("sessionops: NewStarter not wired")
	}
	s, err := deps.NewStarter()
	if err != nil {
		return err
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()

	reply, err := client.OpenSession(ctx, runtime.OpenSessionRequest{
		HostLabel:   *hostLabel,
		ProjectRoot: canonicalRoot,
		TTLSeconds:  int(runtime.DefaultSessionTTL.Seconds()),
	})
	if err != nil {
		return err
	}
	safe := struct {
		SessionID   string    `json:"session_id"`
		HostLabel   string    `json:"host_label"`
		ProjectRoot string    `json:"project_root"`
		ExpiresAt   time.Time `json:"expires_at"`
	}{
		SessionID:   reply.SessionID,
		HostLabel:   reply.HostLabel,
		ProjectRoot: reply.ProjectRoot,
		ExpiresAt:   reply.ExpiresAt,
	}
	renderJSON := deps.RenderJSONOrHuman
	if renderJSON == nil {
		return fmt.Errorf("sessionops: RenderJSONOrHuman not wired")
	}
	renderOpen := deps.RenderSessionOpenResult
	if renderOpen == nil {
		return fmt.Errorf("sessionops: RenderSessionOpenResult not wired")
	}
	return renderJSON(ctx, stdout, *jsonOutput, safe, func(w io.Writer) error {
		return renderOpen(w, safe.SessionID, safe.HostLabel, safe.ProjectRoot, safe.ExpiresAt.Format(secrettypes.TimeRFC3339))
	})
}

// ensureClient calls EnsureDaemon then Connect on the starter.
func ensureClient(ctx context.Context, s Starter) (*runtime.Client, error) {
	if err := s.EnsureDaemon(ctx); err != nil {
		return nil, err
	}
	return s.Connect(ctx)
}
