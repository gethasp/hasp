package app

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

// redactKeys holds the lowercase key substrings that trigger redaction.
// Any Details key whose lowercase form contains one of these strings is redacted.
var redactKeys = []string{"value", "secret_value", "plaintext", "secret", "env_value", "token", "authorization", "credential"}

// redactDetailsForHuman returns a copy of details with sensitive values replaced
// by "[REDACTED]". Keys are matched case-insensitively against redactKeys.
func redactDetailsForHuman(details map[string]any) map[string]any {
	if details == nil {
		return nil
	}
	out := make(map[string]any, len(details))
	for k, v := range details {
		lower := strings.ToLower(k)
		redacted := false
		for _, rk := range redactKeys {
			if strings.Contains(lower, rk) {
				redacted = true
				break
			}
		}
		if redacted {
			out[k] = "[REDACTED]"
		} else {
			out[k] = v
		}
	}
	return out
}

// isBlocked returns true when Details["blocked"] is the bool true or the
// string "true" (case-insensitive).
func isBlocked(details map[string]any) bool {
	if details == nil {
		return false
	}
	v, ok := details["blocked"]
	if !ok {
		return false
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(b, "true")
	}
	return false
}

// fmtDetails returns a compact key=value representation of details after redaction,
// omitting keys that are already shown as dedicated columns (reference, blocked).
func fmtDetails(safe map[string]any) string {
	skipKeys := map[string]bool{"reference": true, "blocked": true}
	var parts []string
	for k, v := range safe {
		if skipKeys[strings.ToLower(k)] {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	if len(parts) == 0 {
		return ""
	}
	// Sort for determinism.
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

// auditRenderTimeline writes one line per event in chronological order.
// Each line contains: timestamp, action, reference, agent, extra details (redacted),
// and "BLOCKED" when applicable. Columns flow through a tabwriter so long
// action types or references can't push later columns out of alignment
// (hasp-wbj2).
func auditRenderTimeline(events []audit.Event, w io.Writer) error {
	// Sort chronologically (earliest first); stable to preserve tie order.
	sorted := make([]audit.Event, len(events))
	copy(sorted, events)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, e := range sorted {
		safe := redactDetailsForHuman(e.Details)

		ref := "-"
		if r, ok := safe["reference"].(string); ok && r != "" {
			ref = r
		}

		ts := e.Timestamp.UTC().Format("2006-01-02 15:04:05")

		extra := fmtDetails(safe)
		blocked := ""
		if isBlocked(e.Details) {
			blocked = "BLOCKED"
		}

		// Five tab-separated columns: timestamp, action, ref, agent, then a
		// trailer that combines extra k=v details and the BLOCKED marker so
		// neither becomes its own ragged column.
		trailer := strings.TrimSpace(strings.Join([]string{extra, blocked}, " "))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", ts, e.Type, ref, e.Actor, trailer)
	}
	return tw.Flush()
}

// auditRenderTable writes a header row followed by one data row per event.
// Columns: time, action, ref, agent, project, blocked, details.
// Sensitive Details values are redacted before rendering.
func auditRenderTable(events []audit.Event, w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	// Header
	fmt.Fprintln(tw, "time\taction\tref\tagent\tproject\tblocked\tdetails")

	for _, e := range events {
		safe := redactDetailsForHuman(e.Details)

		ref := "-"
		if r, ok := safe["reference"].(string); ok && r != "" {
			ref = r
		}

		project := "-"
		if p, ok := safe["project_root"].(string); ok && p != "" {
			project = p
		}

		blocked := "false"
		if isBlocked(e.Details) {
			blocked = "true"
		}

		extra := fmtDetails(safe)
		if extra == "" {
			extra = "-"
		}

		ts := e.Timestamp.UTC().Format("2006-01-02 15:04:05")

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			ts, e.Type, ref, e.Actor, project, blocked, extra)
	}

	return tw.Flush()
}
