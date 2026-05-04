package app

import (
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

type auditFilterOptions struct {
	Secret      string
	ProjectRoot string
	Agent       string
	Action      string
	Blocked     *bool
	Since       time.Time
}

func auditFilterEvents(events []audit.Event, opts auditFilterOptions) []audit.Event {
	out := make([]audit.Event, 0, len(events))
	for _, e := range events {
		if opts.Secret != "" {
			ref, _ := e.Details["reference"].(string)
			if ref != opts.Secret {
				continue
			}
		}
		if opts.ProjectRoot != "" {
			pr, _ := e.Details["project_root"].(string)
			if pr != opts.ProjectRoot {
				continue
			}
		}
		if opts.Agent != "" {
			ag, _ := e.Details["agent"].(string)
			if ag != opts.Agent {
				continue
			}
		}
		if opts.Action != "" {
			ac, _ := e.Details["action"].(string)
			if ac != opts.Action {
				continue
			}
		}
		if opts.Blocked != nil {
			bl, _ := e.Details["blocked"].(bool)
			if bl != *opts.Blocked {
				continue
			}
		}
		if !opts.Since.IsZero() {
			if !e.Timestamp.After(opts.Since) {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}
