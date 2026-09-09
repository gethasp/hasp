package app

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// explainPayload describes a plan before runtime authorization. Grant fields
// are requested scopes, not proof that a lease or secret grant exists.
type explainPayload struct {
	Phase            string            `json:"phase"`
	Checks           map[string]string `json:"checks"`
	Command          string            `json:"command"`
	ProjectRoot      string            `json:"project_root"`
	Target           string            `json:"target,omitempty"`
	ManifestHash     string            `json:"manifest_hash,omitempty"`
	ProjectScope     string            `json:"project_lease"`
	SecretScope      string            `json:"secret_grant"`
	ConvenienceScope string            `json:"convenience_grant,omitempty"`
	GrantWindow      time.Duration     `json:"grant_window"`
	RedactorActive   bool              `json:"redactor_active"`
	RedactorPlanned  bool              `json:"redactor_planned"`
	LiteralEnvNames  []string          `json:"literal_env_names,omitempty"`
	EnvRefs          map[string]string `json:"env_refs,omitempty"`
	FileRefs         map[string]string `json:"file_refs,omitempty"`
	OutputPath       string            `json:"output_path,omitempty"`
	ChildCommand     []string          `json:"child_command,omitempty"`
	DryRun           bool              `json:"dry_run"`
}

func writeExplainPayload(w io.Writer, payload explainPayload, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		out, _ := json.MarshalIndent(payload, "", "  ")
		_, err := fmt.Fprintln(w, string(out))
		return err
	case "text", "":
		return writeExplainText(w, payload)
	default:
		return fmt.Errorf("unknown --explain-format %q (want text or json)", format)
	}
}

func writeExplainText(w io.Writer, payload explainPayload) error {
	var b strings.Builder
	header := "[hasp] execution plan: " + payload.Command
	if payload.DryRun {
		header += " (dry-run)"
	}
	b.WriteString(header)
	b.WriteString("\n")
	fmt.Fprintf(&b, "  project_root:    %s\n", payload.ProjectRoot)
	if payload.Target != "" {
		fmt.Fprintf(&b, "  target:          %s\n", payload.Target)
	}
	if payload.ManifestHash != "" {
		fmt.Fprintf(&b, "  manifest_hash:   %s\n", payload.ManifestHash)
	}
	fmt.Fprintf(&b, "  requested project_lease: %s\n", explainScope(payload.ProjectScope))
	fmt.Fprintf(&b, "  requested secret_grant:  %s\n", explainScope(payload.SecretScope))
	if payload.ConvenienceScope != "" {
		fmt.Fprintf(&b, "  convenience_grant: %s\n", payload.ConvenienceScope)
	}
	fmt.Fprintf(&b, "  grant_window:    %s\n", explainDuration(payload.GrantWindow))
	fmt.Fprintf(&b, "  redactor:        %s\n", explainBool(payload.RedactorPlanned, "planned for child output", "not planned"))
	if len(payload.Checks) > 0 {
		b.WriteString("  checks:\n")
		keys := make([]string, 0, len(payload.Checks))
		for key := range payload.Checks {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(&b, "    %s: %s\n", key, payload.Checks[key])
		}
	}
	if len(payload.LiteralEnvNames) > 0 {
		fmt.Fprintf(&b, "  literal env names: %s\n", strings.Join(payload.LiteralEnvNames, ", "))
	}
	if len(payload.EnvRefs) > 0 {
		b.WriteString("  env refs:\n")
		for _, line := range sortedMappingLines(payload.EnvRefs) {
			b.WriteString("    ")
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	if len(payload.FileRefs) > 0 {
		b.WriteString("  file refs:\n")
		for _, line := range sortedMappingLines(payload.FileRefs) {
			b.WriteString("    ")
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	if payload.OutputPath != "" {
		fmt.Fprintf(&b, "  output_path:     %s\n", payload.OutputPath)
	}
	if len(payload.ChildCommand) > 0 {
		fmt.Fprintf(&b, "  child_command:   %s\n", strings.Join(payload.ChildCommand, " "))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func explainScope(scope string) string {
	if scope == "" {
		return "(not requested)"
	}
	return scope
}

func explainDuration(d time.Duration) string {
	if d <= 0 {
		return "(not requested)"
	}
	return d.String()
}

func explainBool(value bool, on, off string) string {
	if value {
		return on
	}
	return off
}

func sortedMappingLines(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, k+" = "+m[k])
	}
	return lines
}
