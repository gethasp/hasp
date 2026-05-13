package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/jsonwire"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// jsonSchemaVersion is the top-level `_schema` field stamped on every JSON
// response so consumers can detect breaking shape changes (hasp-1dg1). Bump
// when fields are renamed/removed in a way that breaks downstream parsers.
const jsonSchemaVersion = jsonwire.SchemaVersion

// renderJSONOrHuman emits either JSON or the human-readable form of payload.
// jsonOutput is the per-command local flag (e.g. `--json` on the FlagSet); the
// global --json flag from ctx is ORed in so that callers do not need to read
// globalFlagsFromContext themselves. Either flag being true triggers JSON output.
//
// All callers pass their ctx down. When ctx is nil or lacks a globalFlags value
// (e.g. in tests that call helpers directly), only the local jsonOutput flag is
// consulted.
func renderJSONOrHuman(ctx context.Context, stdout io.Writer, jsonOutput bool, payload any, human func(io.Writer) error) error {
	if jsonOutput || globalFlagsFromContext(ctx).json {
		return writeJSONResponse(stdout, payload)
	}
	return human(stdout)
}

// writeJSONResponse marshals payload as JSON, injecting the top-level
// `_schema` field (hasp-1dg1) when the result is a JSON object. Slice/array
// or scalar payloads are written as-is so the helper stays a drop-in
// replacement for json.NewEncoder(...).Encode(...).
func writeJSONResponse(w io.Writer, payload any) error {
	return jsonwire.WriteResponse(w, payload)
}

func cliWriteStage(out io.Writer, title string, lead string) error {
	return cliWriteStageOpts(out, title, lead, ui.ColorOptions{})
}

// cliWriteStageOpts is the opts-aware variant of cliWriteStage. When
// opts.Quiet is true the stage title and success-lead line are suppressed;
// only a blank line is emitted so that subsequent bullet output remains
// correctly spaced.
func cliWriteStageOpts(out io.Writer, title string, lead string, opts ui.ColorOptions) error {
	if opts.Quiet {
		// In quiet mode suppress the title header and success-lead; still
		// emit a blank line so bullet rows that follow are properly separated.
		_, err := fmt.Fprintln(out)
		return err
	}
	if _, err := fmt.Fprintln(out, setupStageHeader(out, title)); err != nil {
		return err
	}
	if strings.TrimSpace(lead) != "" {
		if _, err := fmt.Fprintln(out, cliSuccessLead(out, lead)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(out)
	return err
}

func cliSuccessLead(out io.Writer, text string) string {
	// hasp-41fc: cliLead chooses unicode/ASCII based on the writer.
	return cliLead(out, "1;32", "✓", "[ok]", text)
}

func cliLead(out io.Writer, code string, unicodeSymbol, asciiSymbol, text string) string {
	symbol := cliGlyph(out, unicodeSymbol, asciiSymbol)
	if !setupWriterSupportsColor(out) {
		return symbol + " " + text
	}
	return setupStyle(out, code, symbol) + " " + text
}

func cliSection(out io.Writer, title string) error {
	return setupWriteSummarySection(out, title)
}

func cliWriteKeyValues(out io.Writer, title string, pairs ...[2]string) error {
	// hasp-0kw3: align all values in this block to the longest label
	// (with a 2-char gap) instead of padding every label to a fixed 24
	// columns. Short-key blocks no longer have a giant gutter, and a
	// label longer than 24 no longer pushes its row out of column.
	keep := make([][2]string, 0, len(pairs))
	maxLabel := 0
	for _, pair := range pairs {
		if strings.TrimSpace(pair[1]) == "" {
			continue
		}
		keep = append(keep, pair)
		if n := len(pair[0]); n > maxLabel {
			maxLabel = n
		}
	}
	lines := make([]string, 0, len(keep))
	for _, pair := range keep {
		lines = append(lines, setupSummaryKeyValueAligned(out, pair[0], pair[1], maxLabel))
	}
	return setupWriteKeyValueBlock(out, title, lines...)
}

func cliPair(label string, value string) [2]string {
	return [2]string{label, value}
}

func cliBullet(out io.Writer, label string, details ...string) string {
	bullet := cliGlyph(out, "•", "-")
	line := "  " + setupStyle(out, "1;36", bullet) + " " + setupSummaryLabel(out, label)
	filtered := make([]string, 0, len(details))
	for _, detail := range details {
		if strings.TrimSpace(detail) == "" {
			continue
		}
		filtered = append(filtered, detail)
	}
	if len(filtered) > 0 {
		line += "  " + strings.Join(filtered, "  ")
	}
	return line
}

func cliMuted(out io.Writer, value string) string {
	return setupStyle(out, "2", value)
}

func cliOutcome(out io.Writer, value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "created", "updated", "deleted", "connected", "installed", "disconnected", "exposed", "hidden", "copied", "ok", "initialized", "adopted", "written", "restored", "exported", "bound":
		return setupStyle(out, "1;32", value)
	case "skipped", "already_exposed", "already_hidden", "would_adopt", "preview", "missing":
		return setupStyle(out, "1;33", value)
	case "existing", "unchanged":
		return setupStyle(out, "1;36", value)
	default:
		return setupSummaryValue(out, value)
	}
}

func cliDisplayPath(path string) string {
	return setupDisplayPath(path)
}

func cliPlural(count int, singular string, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

func renderSimpleAction(ctx context.Context, out io.Writer, title string, lead string, pairs ...[2]string) error {
	// hasp-zm35: honour ambient --quiet by suppressing the stage header and
	// success-lead line; the key/value details still print so machine-style
	// callers don't lose the actionable payload.
	opts := ui.ColorOptions{Quiet: globalFlagsFromContext(ctx).quiet}
	if err := cliWriteStageOpts(out, title, lead, opts); err != nil {
		return err
	}
	return cliWriteKeyValues(out, "Details", pairs...)
}

func renderImportCommandResult(out io.Writer, preview importPreview, result *store.ImportResult, applied bool) error {
	title := "Import preview"
	lead := "No changes applied."
	if applied {
		title = "Import complete"
		count := 0
		if result != nil {
			count = len(result.Imported)
		}
		lead = fmt.Sprintf("Imported %d %s into the vault.", count, cliPlural(count, "item", "items"))
	}
	if err := cliWriteStage(out, title, lead); err != nil {
		return err
	}
	if err := cliWriteKeyValues(out, "Source",
		cliPair("Source", preview.Source),
		cliPair("Format", preview.Format),
		cliPair("Capture path", preview.CaptureModeLabel),
		cliPair("Bind to project", setupYesNo(preview.BindToProject)),
	); err != nil {
		return err
	}
	if err := cliSection(out, "Items"); err != nil {
		return err
	}
	if applied && result != nil {
		for _, item := range result.Imported {
			details := []string{cliOutcome(out, string(item.Kind))}
			if item.Alias != "" {
				details = append(details, cliMuted(out, "("+item.Alias+")"))
			}
			if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", item.Name), details...)); err != nil {
				return err
			}
		}
	} else {
		for _, item := range preview.PlannedChanges {
			details := []string{cliOutcome(out, string(item.Kind))}
			if item.Alias != "" {
				details = append(details, cliMuted(out, "("+item.Alias+")"))
			}
			if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", item.Name), details...)); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	if len(preview.Notes) > 0 {
		if err := cliSection(out, "Notes"); err != nil {
			return err
		}
		bullet := cliGlyph(out, "•", "-")
		for _, note := range preview.Notes {
			if _, err := fmt.Fprintln(out, "  "+setupStyle(out, "1;36", bullet)+" "+note); err != nil {
				return err
			}
		}
	}
	return nil
}

func renderSecretMutations(out io.Writer, title string, lead string, values []secretMutationView, missing []string) error {
	if err := cliWriteStage(out, title, lead); err != nil {
		return err
	}
	if len(values) > 0 {
		if err := cliSection(out, "Results"); err != nil {
			return err
		}
		for _, value := range values {
			if _, err := fmt.Fprintln(out, secretMutationLine(out, value)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}
	if len(missing) > 0 {
		if err := cliSection(out, "No change"); err != nil {
			return err
		}
		for _, name := range missing {
			if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", name), cliOutcome(out, "missing"))); err != nil {
				return err
			}
		}
	}
	return nil
}

func secretMutationLine(out io.Writer, value secretMutationView) string {
	details := []string{cliOutcome(out, value.Outcome)}
	if value.Kind != "" {
		details = append(details, setupSummaryValue(out, string(value.Kind)))
	}
	if value.NamedReference != "" {
		details = append(details, cliMuted(out, "("+value.NamedReference+")"))
	}
	if value.Reference != "" {
		details = append(details, cliMuted(out, "("+value.Reference+")"))
	}
	if value.ProjectRoot != "" {
		details = append(details, cliMuted(out, "("+cliDisplayPath(value.ProjectRoot)+")"))
	}
	if len(value.Exposures) > 0 && value.Reference == "" && value.ProjectRoot == "" {
		details = append(details, cliMuted(out, fmt.Sprintf("(%d %s)", len(value.Exposures), cliPlural(len(value.Exposures), "exposure", "exposures"))))
	}
	return cliBullet(out, fmt.Sprintf("%-22s", value.Name), details...)
}

func renderSecretMetadata(out io.Writer, metadata secretMetadataView, copied bool) error {
	lead := "Metadata only. Use --reveal to print the secret value."
	if copied {
		lead = "Copied the secret value to the clipboard."
	}
	if err := cliWriteStage(out, "Secret", lead); err != nil {
		return err
	}
	if err := cliWriteKeyValues(out, "Details",
		cliPair("Name", metadata.Name),
		cliPair("Named ref", metadata.NamedReference),
		cliPair("Kind", string(metadata.Kind)),
		cliPair("Created", metadata.CreatedAt),
		cliPair("Updated", metadata.UpdatedAt),
	); err != nil {
		return err
	}
	return renderSecretExposures(out, metadata.Exposures)
}

func renderSecretExposures(out io.Writer, exposures []store.ItemExposure) error {
	if err := cliSection(out, "Repo exposures"); err != nil {
		return err
	}
	if len(exposures) == 0 {
		_, err := fmt.Fprintln(out, "  none")
		return err
	}
	for _, exposure := range exposures {
		if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", exposure.Reference), cliMuted(out, "("+cliDisplayPath(exposure.ProjectRoot)+")"))); err != nil {
			return err
		}
	}
	return nil
}

func renderSecretList(out io.Writer, secrets []secretMetadataView) error {
	return renderSecretListWithColor(out, secrets, ui.ColorOptions{Interactive: ui.IsInteractiveWriter(out)})
}

// renderSecretListWithColor adds a per-row state badge (vault-only/shared)
// using the security-tool palette. Vault-only secrets are green (the
// cleanest state for a stored secret); secrets bound to one or more repos
// are yellow (shared — worth a glance to confirm the bindings are
// intentional). The existing cli_output styling is left intact for the
// rest of the row so the human-readable layer keeps its contract.
func renderSecretListWithColor(out io.Writer, secrets []secretMetadataView, opts ui.ColorOptions) error {
	lead := "No secrets stored in the vault."
	if len(secrets) > 0 {
		lead = fmt.Sprintf("%d %s available in the vault.", len(secrets), cliPlural(len(secrets), "secret", "secrets"))
	}
	if err := cliWriteStageOpts(out, "Vault secrets", lead, opts); err != nil {
		return err
	}
	if len(secrets) == 0 {
		return nil
	}
	if err := cliSection(out, "Secrets"); err != nil {
		return err
	}
	for _, secret := range secrets {
		badge := secretStateBadge(secret, opts)
		details := []string{
			setupSummaryValue(out, string(secret.Kind)),
			cliMuted(out, "("+secret.NamedReference+")"),
			cliMuted(out, "(updated "+secret.UpdatedAt+")"),
		}
		if opts.Verbose && secret.CreatedAt != "" {
			details = append(details, cliMuted(out, "(created "+secret.CreatedAt+")"))
		}
		if len(secret.Exposures) > 0 {
			details = append(details, cliMuted(out, fmt.Sprintf("(%d %s)", len(secret.Exposures), cliPlural(len(secret.Exposures), "repo exposure", "repo exposures"))))
		}
		label := badge + " " + fmt.Sprintf("%-22s", secret.Name)
		if _, err := fmt.Fprintln(out, cliBullet(out, label, details...)); err != nil {
			return err
		}
		for _, exposure := range secret.Exposures {
			path := exposure.ProjectRoot
			if !opts.Verbose {
				path = cliDisplayPath(path)
			}
			if _, err := fmt.Fprintln(out, "    "+exposure.Reference+"  "+cliMuted(out, path)); err != nil {
				return err
			}
		}
	}
	return nil
}

func secretStateBadge(secret secretMetadataView, opts ui.ColorOptions) string {
	if len(secret.Exposures) == 0 {
		return ui.Colorize("[vault-only]", ui.ColorOK, opts)
	}
	return ui.Colorize("[shared]", ui.ColorWarn, opts)
}

// secretGetJSONPayload builds the JSON envelope for secret show/reveal/copy.
//
// Shape migration (hasp-jx3r): "value" / "value_base64" are now nested inside
// "secret" rather than sitting at the top level. Consumers: jq -r .secret.value
// (was: jq -r .value). The "copied" flag remains at the top level as it is
// operational metadata, not secret content.
func secretGetJSONPayload(metadata secretMetadataView, copied bool, reveal bool, value []byte) map[string]any {
	// Build the secret sub-object as a plain map so we can add optional fields
	// without touching the secretMetadataView struct.
	secretObj := map[string]any{
		"name":       metadata.Name,
		"kind":       metadata.Kind,
		"created_at": metadata.CreatedAt,
		"updated_at": metadata.UpdatedAt,
		"exposures":  metadata.Exposures,
	}
	if metadata.NamedReference != "" {
		secretObj["named_reference"] = metadata.NamedReference
	}
	if reveal {
		if utf8.Valid(value) {
			secretObj["value"] = string(value)
		} else {
			secretObj["value_base64"] = base64.StdEncoding.EncodeToString(value)
		}
	}
	payload := map[string]any{"secret": secretObj}
	if copied {
		payload["copied"] = true
	}
	return payload
}

func renderProjectBinding(out io.Writer, title string, lead string, binding store.Binding) error {
	if err := cliWriteStage(out, title, lead); err != nil {
		return err
	}
	if err := cliWriteKeyValues(out, "Project",
		cliPair("Project root", cliDisplayPath(binding.CanonicalRoot)),
		cliPair("Binding ID", binding.ID),
		cliPair("Default policy", string(binding.DefaultCapturePolicy)),
		cliPair("Hooks installed", setupYesNo(binding.HookInstalled)),
	); err != nil {
		return err
	}
	return renderBindingAliases(out, binding.Aliases)
}

func renderBindingAliases(out io.Writer, aliases map[string]string) error {
	if err := cliSection(out, "Aliases"); err != nil {
		return err
	}
	if len(aliases) == 0 {
		_, err := fmt.Fprintln(out, "  none")
		return err
	}
	keys := make([]string, 0, len(aliases))
	for alias := range aliases {
		keys = append(keys, alias)
	}
	sort.Strings(keys)
	for _, alias := range keys {
		if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", alias), cliMuted(out, "("+aliases[alias]+")"))); err != nil {
			return err
		}
	}
	return nil
}

func renderProjectStatus(out io.Writer, binding store.Binding, visible []store.VisibleReference) error {
	if err := renderProjectBinding(out, "Project status", "Loaded the current project boundary.", binding); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	if err := cliSection(out, "Visible references"); err != nil {
		return err
	}
	if len(visible) == 0 {
		_, err := fmt.Fprintln(out, "  none")
		return err
	}
	for _, ref := range visible {
		if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", ref.Alias),
			cliMuted(out, "("+ref.NamedReference+")"),
			setupSummaryValue(out, string(ref.Kind)),
			setupSummaryValue(out, string(ref.PolicyLevel)),
			cliMuted(out, "("+ref.LeaseStatus+")"),
		)); err != nil {
			return err
		}
	}
	return nil
}

func renderProjectAdoptResult(out io.Writer, result projectAdoptResult) error {
	lead := fmt.Sprintf("Scanned %d %s and adopted %d.", result.ScannedRoots, cliPlural(result.ScannedRoots, "repo", "repos"), result.AdoptedCount)
	if result.Preview {
		lead = fmt.Sprintf("Previewed %d %s under %s.", result.ScannedRoots, cliPlural(result.ScannedRoots, "repo", "repos"), cliDisplayPath(result.Under))
	}
	if err := cliWriteStage(out, "Project adoption", lead); err != nil {
		return err
	}
	if err := cliWriteKeyValues(out, "Defaults",
		cliPair("Under", cliDisplayPath(result.Under)),
		cliPair("Preview", setupYesNo(result.Preview)),
		cliPair("Default policy", string(result.Defaults.DefaultPolicy)),
		cliPair("Install hooks", setupYesNo(result.Defaults.AutoInstallHooks)),
	); err != nil {
		return err
	}
	if err := cliSection(out, "Candidates"); err != nil {
		return err
	}
	if len(result.Candidates) == 0 {
		_, err := fmt.Fprintln(out, "  none")
		return err
	}
	for _, candidate := range result.Candidates {
		outcome := candidate.Reason
		if candidate.Adopted {
			outcome = "adopted"
		} else if candidate.AlreadyManaged {
			outcome = "already managed"
		}
		if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", cliDisplayPath(candidate.ProjectRoot)),
			cliOutcome(out, outcome),
			cliMuted(out, "(hooks "+setupYesNo(candidate.HooksEnabled)+")"),
		)); err != nil {
			return err
		}
	}
	return nil
}

func renderAppConsumerSummary(out io.Writer, title string, lead string, consumer store.AppConsumer, pathUpdate appPathUpdateResult) error {
	if err := cliWriteStage(out, title, lead); err != nil {
		return err
	}
	if err := cliWriteKeyValues(out, "App",
		cliPair("Name", consumer.Name),
		cliPair("Project root", cliDisplayPath(consumer.ProjectRoot)),
		cliPair("Command", strings.Join(consumer.Command, " ")),
		cliPair("Launcher", cliDisplayPath(consumer.LauncherPath)),
		cliPair("Bindings", fmt.Sprintf("%d", len(consumer.Bindings))),
	); err != nil {
		return err
	}
	if len(consumer.Bindings) > 0 {
		if err := cliSection(out, "Bindings"); err != nil {
			return err
		}
		for _, binding := range consumer.Bindings {
			if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", binding.Target),
				setupSummaryValue(out, string(binding.Delivery)),
				cliMuted(out, "("+binding.SecretName+")"),
			)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}
	if pathUpdate.Changed || strings.TrimSpace(pathUpdate.ConfigPath) != "" {
		if err := cliWriteKeyValues(out, "PATH update",
			cliPair("Changed", setupYesNo(pathUpdate.Changed)),
			cliPair("Config path", cliDisplayPath(pathUpdate.ConfigPath)),
		); err != nil {
			return err
		}
	}
	return nil
}

func renderAppConsumerList(out io.Writer, consumers []store.AppConsumer) error {
	lead := "No saved apps."
	if len(consumers) > 0 {
		lead = fmt.Sprintf("%d saved %s.", len(consumers), cliPlural(len(consumers), "app", "apps"))
	}
	if err := cliWriteStage(out, "Apps", lead); err != nil {
		return err
	}
	if len(consumers) == 0 {
		return nil
	}
	if err := cliSection(out, "Apps"); err != nil {
		return err
	}
	for _, consumer := range consumers {
		details := []string{cliMuted(out, fmt.Sprintf("(%d %s)", len(consumer.Bindings), cliPlural(len(consumer.Bindings), "binding", "bindings")))}
		if consumer.LauncherPath != "" {
			details = append(details, cliMuted(out, "("+cliDisplayPath(consumer.LauncherPath)+")"))
		}
		if consumer.ProjectRoot != "" {
			details = append(details, cliMuted(out, "("+cliDisplayPath(consumer.ProjectRoot)+")"))
		}
		if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", consumer.Name), details...)); err != nil {
			return err
		}
	}
	return nil
}

func renderAgentConsumerSummary(out io.Writer, title string, lead string, consumer store.AgentConsumer, outcome setupAgentOutcome) error {
	if err := cliWriteStage(out, title, lead); err != nil {
		return err
	}
	return cliWriteKeyValues(out, "Agent",
		cliPair("Name", consumer.Name),
		cliPair("Agent ID", consumer.AgentID),
		cliPair("Project root", cliDisplayPath(consumer.ProjectRoot)),
		cliPair("Config path", cliDisplayPath(consumer.ConfigPath)),
		cliPair("Changed", setupYesNo(outcome.Changed)),
		cliPair("Backup path", cliDisplayPath(outcome.BackupPath)),
	)
}

func renderAgentConsumerList(out io.Writer, consumers []store.AgentConsumer) error {
	lead := "No connected agents."
	if len(consumers) > 0 {
		lead = fmt.Sprintf("%d connected %s.", len(consumers), cliPlural(len(consumers), "agent", "agents"))
	}
	if err := cliWriteStage(out, "Agents", lead); err != nil {
		return err
	}
	if len(consumers) == 0 {
		return nil
	}
	if err := cliSection(out, "Agents"); err != nil {
		return err
	}
	for _, consumer := range consumers {
		details := []string{
			cliMuted(out, "("+consumer.AgentID+")"),
			cliMuted(out, "("+cliDisplayPath(consumer.ConfigPath)+")"),
		}
		if consumer.ProjectRoot != "" {
			details = append(details, cliMuted(out, "("+cliDisplayPath(consumer.ProjectRoot)+")"))
		}
		if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", consumer.Name), details...)); err != nil {
			return err
		}
	}
	return nil
}

func renderWriteEnvResult(out io.Writer, outputPath string, entries int, warning string) error {
	lead := fmt.Sprintf("Wrote %d %s to the env file.", entries, cliPlural(entries, "entry", "entries"))
	if err := cliWriteStage(out, "Env file written", lead); err != nil {
		return err
	}
	return cliWriteKeyValues(out, "Details",
		cliPair("Output path", cliDisplayPath(outputPath)),
		cliPair("Entries", fmt.Sprintf("%d", entries)),
		cliPair("Warning", warning),
	)
}

func renderRepoCheckResult(out io.Writer, projectRoot string, matches []map[string]string, override bool, warning ...string) error {
	warningText := ""
	if len(warning) > 0 {
		warningText = warning[0]
	}
	lead := "No managed values were detected in repository files."
	if warningText != "" {
		lead = "Repo files were scanned, but managed-value matching was skipped."
	}
	if len(matches) > 0 {
		lead = fmt.Sprintf("Detected %d managed %s in repository files.", len(matches), cliPlural(len(matches), "value", "values"))
	}
	if err := cliWriteStage(out, "Repo check", lead); err != nil {
		return err
	}
	if err := cliWriteKeyValues(out, "Details",
		cliPair("Project root", cliDisplayPath(projectRoot)),
		cliPair("Override", setupYesNo(override)),
		cliPair("Warning", warningText),
	); err != nil {
		return err
	}
	if len(matches) == 0 {
		return nil
	}
	if err := cliSection(out, "Matches"); err != nil {
		return err
	}
	for _, match := range matches {
		if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", cliDisplayPath(match["path"])), cliMuted(out, "("+match["item_name"]+")"))); err != nil {
			return err
		}
	}
	return nil
}

func renderBackupResult(out io.Writer, title string, lead string, path string, checkpoint store.AuditCheckpoint) error {
	if err := cliWriteStage(out, title, lead); err != nil {
		return err
	}
	return cliWriteKeyValues(out, "Details",
		cliPair("Path", cliDisplayPath(path)),
		cliPair("Audit sequence", fmt.Sprintf("%d", checkpoint.Sequence)),
		cliPair("Audit hash", checkpoint.Hash),
	)
}

func renderPingResult(out io.Writer, reply runtime.PingResponse) error {
	if err := cliWriteStage(out, "Daemon reachable", "The local HASP daemon responded."); err != nil {
		return err
	}
	return cliWriteKeyValues(out, "Daemon",
		cliPair("Name", reply.Name),
		cliPair("Version", reply.Version),
		cliPair("Server time", reply.ServerTime.Format(secrettypes.TimeRFC3339)),
	)
}

func renderSessionOpenResult(out io.Writer, sessionID string, hostLabel string, projectRoot string, expiresAt string) error {
	if err := cliWriteStage(out, "Session opened", "Opened a new daemon-backed session."); err != nil {
		return err
	}
	return cliWriteKeyValues(out, "Session",
		cliPair("Session ID", sessionID),
		cliPair("Host label", hostLabel),
		cliPair("Project root", cliDisplayPath(projectRoot)),
		cliPair("Expires", expiresAt),
	)
}

func renderSessionResolveResult(out io.Writer, reply runtime.ResolveSessionResponse) error {
	if err := cliWriteStage(out, "Session", "Resolved the requested daemon-backed session."); err != nil {
		return err
	}
	return cliWriteKeyValues(out, "Session",
		cliPair("Session ID", reply.Session.ID),
		cliPair("Local user", reply.Session.LocalUser),
		cliPair("Host label", reply.Session.HostLabel),
		cliPair("Project root", cliDisplayPath(reply.Session.ProjectRoot)),
		cliPair("Last seen", reply.Session.LastSeenAt.Format(secrettypes.TimeRFC3339)),
		cliPair("Expires", reply.Session.ExpiresAt.Format(secrettypes.TimeRFC3339)),
	)
}

func renderBootstrapSummary(out io.Writer, result bootstrapResult) error {
	lead := fmt.Sprintf("Configured %s for %s.", result.Profile.Name, cliDisplayPath(result.ProjectRoot))
	if err := cliWriteStage(out, "Bootstrap complete", lead); err != nil {
		return err
	}
	if err := cliWriteKeyValues(out, "Profile",
		cliPair("Profile", result.Profile.Name),
		cliPair("Support tier", result.SupportTier),
		cliPair("Compatibility", result.CompatibilityLabel),
		cliPair("First class", setupYesNo(result.FirstClass)),
		cliPair("Project root", cliDisplayPath(result.ProjectRoot)),
		cliPair("Init state", result.InitState),
		cliPair("Hooks enabled", setupYesNo(result.HooksEnabled)),
		cliPair("Binding ID", result.Binding.ID),
	); err != nil {
		return err
	}
	if len(result.BoundAliases) > 0 {
		if err := cliSection(out, "Bound aliases"); err != nil {
			return err
		}
		keys := make([]string, 0, len(result.BoundAliases))
		for alias := range result.BoundAliases {
			keys = append(keys, alias)
		}
		sort.Strings(keys)
		for _, alias := range keys {
			if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", alias), cliMuted(out, "("+result.BoundAliases[alias]+")"))); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}
	if len(result.Imported) > 0 {
		if err := cliSection(out, "Imported items"); err != nil {
			return err
		}
		for _, item := range result.Imported {
			details := []string{setupSummaryValue(out, string(item.Kind))}
			if item.Alias != "" {
				details = append(details, cliMuted(out, "("+item.Alias+")"))
			}
			if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", item.Name), details...)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}
	if len(result.NextSteps) > 0 {
		if err := cliSection(out, "Next steps"); err != nil {
			return err
		}
		for idx, step := range result.NextSteps {
			if _, err := fmt.Fprintln(out, setupSummaryStepLine(out, idx+1, step)); err != nil {
				return err
			}
		}
	}
	return nil
}

func renderBootstrapDoctorSummary(out io.Writer, report bootstrapDoctorResult) error {
	lead := fmt.Sprintf("Checked bootstrap readiness for %s.", cliDisplayPath(report.ProjectCanonicalRoot))
	if err := cliWriteStage(out, "Bootstrap doctor", lead); err != nil {
		return err
	}
	if err := cliWriteKeyValues(out, "Context",
		cliPair("Profile", report.Profile.Name),
		cliPair("Support tier", report.SupportTier),
		cliPair("Project root", cliDisplayPath(report.ProjectCanonicalRoot)),
		cliPair("Vault status", report.VaultStatus),
		cliPair("Hooks requested", setupYesNo(report.HooksRequested)),
		cliPair("Hooks present", setupYesNo(report.HooksPresent)),
	); err != nil {
		return err
	}
	if err := cliSection(out, "Checks"); err != nil {
		return err
	}
	checkNames := make([]string, 0, len(report.Checks))
	for name := range report.Checks {
		checkNames = append(checkNames, name)
	}
	sort.Strings(checkNames)
	for _, name := range checkNames {
		check := report.Checks[name]
		details := []string{cliOutcome(out, check.Status)}
		if check.Detail != "" {
			details = append(details, cliMuted(out, "("+check.Detail+")"))
		}
		if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", name), details...)); err != nil {
			return err
		}
	}
	if len(report.PlannedImportSummary) > 0 {
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
		if err := cliSection(out, "Planned imports"); err != nil {
			return err
		}
		for _, summary := range report.PlannedImportSummary {
			source, _ := summary["source"].(string)
			format, _ := summary["format"].(string)
			if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", source), cliMuted(out, "("+format+")"))); err != nil {
				return err
			}
		}
	}
	return nil
}

func renderBootstrapProfilesSummary(out io.Writer, listing map[string]any) error {
	rawProfiles, _ := listing["profiles"].([]map[string]any)
	if rawProfiles == nil {
		if values, ok := listing["profiles"].([]any); ok {
			rawProfiles = make([]map[string]any, 0, len(values))
			for _, value := range values {
				if typed, ok := value.(map[string]any); ok {
					rawProfiles = append(rawProfiles, typed)
				}
			}
		}
	}
	lead := fmt.Sprintf("%d shipped %s available.", len(rawProfiles), cliPlural(len(rawProfiles), "profile", "profiles"))
	if err := cliWriteStage(out, "Bootstrap profiles", lead); err != nil {
		return err
	}
	if len(rawProfiles) == 0 {
		return nil
	}
	if err := cliSection(out, "Profiles"); err != nil {
		return err
	}
	for _, profile := range rawProfiles {
		id, _ := profile["id"].(string)
		supportTier, _ := profile["support_tier"].(string)
		transport, _ := profile["transport"].(string)
		if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", id), setupSummaryValue(out, supportTier), cliMuted(out, "("+transport+")"))); err != nil {
			return err
		}
	}
	if generic, ok := listing["generic_path"].(map[string]any); ok {
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
		if err := cliSection(out, "Generic-compatible first proof"); err != nil {
			return err
		}
		id, _ := generic["id"].(string)
		tier, _ := generic["support_tier"].(string)
		transport, _ := generic["transport"].(string)
		setupCommand, _ := generic["setup_command"].(string)
		firstProofCommand, _ := generic["first_proof_command"].(string)
		if _, err := fmt.Fprintln(out, cliBullet(out, fmt.Sprintf("%-22s", id), setupSummaryValue(out, tier), cliMuted(out, "("+transport+")"))); err != nil {
			return err
		}
		if strings.TrimSpace(setupCommand) != "" {
			if _, err := fmt.Fprintln(out, "  "+cliMuted(out, "setup:")+" "+setupCommand); err != nil {
				return err
			}
		}
		if strings.TrimSpace(firstProofCommand) != "" {
			if _, err := fmt.Fprintln(out, "  "+cliMuted(out, "first proof:")+" "+firstProofCommand); err != nil {
				return err
			}
		}
	}
	return nil
}

func renderBootstrapProfileListingMaybeHuman(ctx context.Context, out io.Writer, jsonOutput bool, listing map[string]any) error {
	return renderJSONOrHuman(ctx, out, jsonOutput, listing, func(w io.Writer) error {
		return renderBootstrapProfilesSummary(w, listing)
	})
}

func renderPingJSONOrHuman(ctx context.Context, out io.Writer, jsonOutput bool, reply runtime.PingResponse) error {
	return renderJSONOrHuman(ctx, out, jsonOutput, reply, func(w io.Writer) error {
		return renderPingResult(w, reply)
	})
}

func renderBootstrapJSONOrHuman(ctx context.Context, out io.Writer, jsonOutput bool, result bootstrapResult) error {
	return renderJSONOrHuman(ctx, out, jsonOutput, result, func(w io.Writer) error {
		return renderBootstrapSummary(w, result)
	})
}

func renderBootstrapDoctorJSONOrHuman(ctx context.Context, out io.Writer, jsonOutput bool, report bootstrapDoctorResult) error {
	return renderJSONOrHuman(ctx, out, jsonOutput, report, func(w io.Writer) error {
		return renderBootstrapDoctorSummary(w, report)
	})
}

func renderSecretListJSONOrHuman(ctx context.Context, out io.Writer, jsonOutput bool, secrets []secretMetadataView) error {
	gf := globalFlagsFromContext(ctx)
	opts := ui.ColorOptions{Interactive: ui.IsInteractiveWriter(out), Disable: gf.noColor, Quiet: gf.quiet, Verbose: gf.verbose}
	return renderSecretListJSONOrHumanWithColor(ctx, out, jsonOutput, secrets, opts)
}

func renderSecretListJSONOrHumanWithColor(ctx context.Context, out io.Writer, jsonOutput bool, secrets []secretMetadataView, opts ui.ColorOptions) error {
	payload := map[string]any{"secrets": secrets}
	return renderJSONOrHuman(ctx, out, jsonOutput, payload, func(w io.Writer) error {
		return renderSecretListWithColor(w, secrets, opts)
	})
}

// renderSecretSearchJSONOrHuman renders a search result with distinct messages
// for three cases:
//   - matches found: delegates to renderSecretListWithColor (normal list output)
//   - vault non-empty but no matches: "no matches for <query>" message
//   - vault empty: the canonical "No secrets stored in the vault." message
//
// The JSON payload always includes total (vault size before filtering) and
// match_count so callers can distinguish the three cases without parsing text.
func renderSecretSearchJSONOrHuman(ctx context.Context, out io.Writer, jsonOutput bool, query string, total int, secrets []secretMetadataView, opts ui.ColorOptions) error {
	payload := map[string]any{
		"secrets":     secrets,
		"total":       total,
		"match_count": len(secrets),
	}
	return renderJSONOrHuman(ctx, out, jsonOutput, payload, func(w io.Writer) error {
		// Matches found — render as a normal list.
		if len(secrets) > 0 {
			return renderSecretListWithColor(w, secrets, opts)
		}
		// Vault is empty — use the canonical empty-vault message.
		if total == 0 {
			return renderSecretListWithColor(w, secrets, opts)
		}
		// Vault has items but none matched the query.
		lead := fmt.Sprintf("No matches for %q in the vault (%d %s searched).", query, total, cliPlural(total, "secret", "secrets"))
		return cliWriteStageOpts(w, "Vault secrets", lead, opts)
	})
}
