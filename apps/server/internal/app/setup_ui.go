package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

func renderSetupSummary(out io.Writer, summary setupSummary) error {
	if err := setupWriteStage(out, "Setup complete"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, setupSummaryLead(out, "HASP is configured for this machine.")); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	if err := setupWriteKeyValueBlock(out, "Machine",
		setupSummaryKeyValue(out, "Local HASP data", summary.HaspHome),
		setupSummaryKeyValue(out, "Saved CLI config", summary.ConfigPath),
	); err != nil {
		return err
	}
	defaults := []string{
		setupSummaryKeyValue(out, "Automatic repo adoption", setupEnabledDisabled(summary.AutoProtectRepos)),
		setupSummaryKeyValue(out, "Automatic repo guardrails", setupYesNo(summary.AutoInstallHooks)),
		setupSummaryKeyValue(out, "Vault state", summary.InitState),
		setupSummaryKeyValue(out, "Convenience unlock", summary.ConvenienceUnlock),
	}
	if strings.TrimSpace(summary.ConvenienceDetail) != "" {
		defaults = append(defaults, setupSummaryKeyValue(out, "Convenience detail", summary.ConvenienceDetail))
	}
	if strings.TrimSpace(summary.ProjectRoot) != "" {
		defaults = append(defaults, setupSummaryKeyValue(out, "Protected repository", summary.ProjectRoot))
	}
	if err := setupWriteKeyValueBlock(out, "Defaults", defaults...); err != nil {
		return err
	}
	if len(summary.Agents) > 0 {
		if err := setupWriteSummarySection(out, "Configured agents"); err != nil {
			return err
		}
		for _, agent := range summary.Agents {
			if _, err := fmt.Fprintln(out, setupSummaryAgentLine(out, agent)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}
	if len(summary.AddedSecrets) > 0 {
		if err := setupWriteSummarySection(out, "Added secrets"); err != nil {
			return err
		}
		for _, secret := range summary.AddedSecrets {
			if _, err := fmt.Fprintln(out, setupSummarySecretLine(out, secret)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}
	if len(summary.Apps) > 0 {
		if err := setupWriteSummarySection(out, "Connected apps"); err != nil {
			return err
		}
		for _, app := range summary.Apps {
			if _, err := fmt.Fprintln(out, setupSummaryAppLine(out, app)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}
	if len(summary.Verification) > 0 {
		if err := setupWriteSummarySection(out, "Verification"); err != nil {
			return err
		}
		if mcpReady, ok := summary.Verification["mcp"].(map[string]any); ok {
			ready, _ := mcpReady["ready"].(bool)
			status := "not-ready"
			if ready {
				status = "ready"
			}
			if _, err := fmt.Fprintln(out, cliBullet(out, "MCP tools/list", setupSummaryValue(out, status))); err != nil {
				return err
			}
		}
		if proof, ok := summary.Verification["brokered_proof"].(map[string]any); ok {
			performed, _ := proof["performed"].(bool)
			ready, _ := proof["ready"].(bool)
			ref, _ := proof["reference"].(string)
			reason, _ := proof["reason"].(string)
			proofState, _ := proof["state"].(string)
			status := "skipped"
			switch {
			case performed:
				status = "passed"
			case ready || proofState == "ready":
				status = "ready"
			case strings.TrimSpace(reason) != "" || proofState == "unavailable":
				status = "unavailable"
			}
			details := []string{setupSummaryValue(out, status)}
			if strings.TrimSpace(ref) != "" {
				details = append(details, cliMuted(out, "("+ref+")"))
			}
			if strings.TrimSpace(reason) != "" {
				details = append(details, cliMuted(out, "("+reason+")"))
			}
			if _, err := fmt.Fprintln(out, cliBullet(out, "Brokered proof", details...)); err != nil {
				return err
			}
			rescue, hasRescue := proof["rescue"].(map[string]any)
			if hasRescue {
				if proofState == "unavailable" {
					rescueAvailable, _ := rescue["available"].(bool)
					if rescueAvailable {
						if _, err := fmt.Fprintln(out, cliMuted(out, "  Inline rescue — add a managed reference using one of:")); err != nil {
							return err
						}
						switch cmds := rescue["commands"].(type) {
						case []string:
							for _, cmd := range cmds {
								if _, err := fmt.Fprintln(out, "    "+cmd); err != nil {
									return err
								}
							}
						case []any:
							for _, raw := range cmds {
								if cmd, ok := raw.(string); ok {
									if _, err := fmt.Fprintln(out, "    "+cmd); err != nil {
										return err
									}
								}
							}
						}
					}
				}
				rescuePerformed, _ := rescue["performed"].(bool)
				nextCmd, _ := rescue["next_command"].(string)
				if rescuePerformed && strings.TrimSpace(nextCmd) != "" {
					if _, err := fmt.Fprintln(out, cliMuted(out, "  Run the brokered proof: "+nextCmd)); err != nil {
						return err
					}
				}
			}
			// Surface the proof command directly when state is ready (and it wasn't
			// already shown via rescue.next_command after a rescue).
			if proofState == "ready" && strings.TrimSpace(ref) != "" {
				cmd, _ := proof["command"].(string)
				if strings.TrimSpace(cmd) != "" {
					if _, err := fmt.Fprintln(out, cliMuted(out, "  Proof command: "+cmd)); err != nil {
						return err
					}
				}
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}
	if len(summary.NextSteps) > 0 {
		if err := setupWriteSummarySection(out, "Next steps"); err != nil {
			return err
		}
		for idx, step := range summary.NextSteps {
			if _, err := fmt.Fprintln(out, setupSummaryStepLine(out, idx+1, step)); err != nil {
				return err
			}
		}
	}
	return nil
}

func setupWriteIntro(out io.Writer) error {
	return setupWriteStage(out, "HASP setup",
		"HASP setup will:",
		"1. choose where local encrypted HASP data lives on this machine",
		"2. set defaults for automatically protecting repos on first use",
		"3. optionally configure coding agents, add vault secrets, and connect one app",
		"4. verify the local broker path and surface a first proof command when a bound secret is available",
		"Press Enter to accept the default shown in brackets.",
	)
}

func setupWriteStage(out io.Writer, title string, lines ...string) error {
	if _, err := fmt.Fprintln(out, setupStageHeader(out, title)); err != nil {
		return err
	}
	prevLine := ""
	for _, line := range lines {
		if setupShouldSeparateStageLines(prevLine, line) {
			if _, err := fmt.Fprintln(out); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out, setupStageLine(out, line)); err != nil {
			return err
		}
		if strings.TrimSpace(line) != "" {
			prevLine = line
		}
	}
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	return nil
}

func setupStageHeader(out io.Writer, title string) string {
	text := "== " + title + " =="
	return setupStyle(out, "1;36", text)
}

func setupStageLine(out io.Writer, line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(line, "   config: ") {
		return "   " + setupSummaryLabel(out, "config") + ": " + setupSummaryValue(out, strings.TrimPrefix(line, "   config: "))
	}
	switch {
	case strings.HasPrefix(trimmed, "-"),
		strings.HasPrefix(trimmed, "1."),
		strings.HasPrefix(trimmed, "2."),
		strings.HasPrefix(trimmed, "3."),
		strings.HasPrefix(trimmed, "4."),
		strings.HasPrefix(trimmed, "5."),
		strings.HasPrefix(trimmed, "6."),
		strings.HasPrefix(trimmed, "7."),
		strings.HasPrefix(trimmed, "8."),
		strings.HasPrefix(trimmed, "9."),
		strings.HasPrefix(trimmed, "10."):
		if prefix, rest, ok := setupSplitNumericPrefix(trimmed); ok {
			return "  " + setupStyle(out, "1;36", prefix) + " " + rest
		}
		return "  " + line
	case strings.HasPrefix(line, "   "):
		return line
	default:
		return "  " + setupStyle(out, "36", cliGlyph(out, "•", "-")) + " " + line
	}
}

func setupShouldSeparateStageLines(prev string, current string) bool {
	prevKind := setupStageLineKind(prev)
	currentKind := setupStageLineKind(current)
	switch {
	case prevKind == "numeric" && currentKind == "text":
		return true
	case prevKind == "text" && currentKind == "numeric":
		return !strings.HasSuffix(strings.TrimSpace(prev), ":")
	default:
		return false
	}
}

func setupStageLineKind(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(line, "   config: ") {
		return "config"
	}
	if _, _, ok := setupSplitNumericPrefix(trimmed); ok {
		return "numeric"
	}
	if strings.HasPrefix(trimmed, "-") {
		return "dash"
	}
	if strings.HasPrefix(line, "   ") {
		return "indented"
	}
	return "text"
}

func setupWriterSupportsColor(out io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	file, ok := out.(*os.File)
	if !ok || file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func setupSummaryLead(out io.Writer, text string) string {
	// hasp-41fc: drop unicode glyph on non-color writers and non-UTF-8 locales.
	glyph := cliGlyph(out, "✓", "[ok]")
	if !setupWriterSupportsColor(out) {
		return glyph + " " + text
	}
	return "\x1b[1;32m" + glyph + "\x1b[0m " + text
}

func setupWriteKeyValueBlock(out io.Writer, title string, lines ...string) error {
	if len(lines) == 0 {
		return nil
	}
	if err := setupWriteSummarySection(out, title); err != nil {
		return err
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	return nil
}

func setupWriteSummarySection(out io.Writer, title string) error {
	if _, err := fmt.Fprintln(out, setupSummarySectionHeader(out, title)); err != nil {
		return err
	}
	return nil
}

func setupSummarySectionHeader(out io.Writer, title string) string {
	return setupStyle(out, "1", title)
}

func setupSummaryKeyValue(out io.Writer, label string, value string) string {
	return setupSummaryKeyValueAligned(out, label, value, 24)
}

// setupSummaryKeyValueAligned pads label to width chars (rune-counted) so a
// caller computing a per-block max width can align all values to the same
// column without the legacy fixed-24 gutter.
func setupSummaryKeyValueAligned(out io.Writer, label string, value string, width int) string {
	pad := width - len(label)
	if pad < 0 {
		pad = 0
	}
	padded := label + strings.Repeat(" ", pad)
	return "  " + setupSummaryLabel(out, padded) + "  " + setupSummaryValue(out, value)
}

func setupSummaryLabel(out io.Writer, text string) string {
	return setupStyle(out, "1", text)
}

func setupSummaryValue(out io.Writer, value string) string {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	switch lower {
	case "yes", "enabled", "enabled when available", "updated", "created":
		return setupStyle(out, "1;32", value)
	case "no", "disabled", "unavailable", "skip for now":
		return setupStyle(out, "1;33", value)
	case "existing", "unchanged":
		return setupStyle(out, "1;36", value)
	}
	if strings.HasPrefix(trimmed, "~") || strings.HasPrefix(trimmed, "/") {
		return setupStyle(out, "36", value)
	}
	return value
}

func setupSummaryAgentLine(out io.Writer, agent setupAgentOutcome) string {
	status := "updated"
	if !agent.Changed {
		status = "unchanged"
	}
	icon := cliGlyph(out, "✓", "[ok]")
	if !agent.Changed {
		icon = cliGlyph(out, "•", "-")
	}
	return "  " + setupStyle(out, "1;32", icon) + " " +
		setupSummaryLabel(out, fmt.Sprintf("%-18s", agent.Label)) + "  " +
		setupSummaryValue(out, agent.ConfigPath) + "  " +
		setupStyle(out, "2", "("+status+")")
}

func setupSummarySecretLine(out io.Writer, secret secretMutationView) string {
	line := "  " + setupStyle(out, "1;32", cliGlyph(out, "•", "-")) + " " +
		setupSummaryLabel(out, fmt.Sprintf("%-18s", secret.Name)) + "  " +
		setupSummaryValue(out, secret.Outcome)
	if strings.TrimSpace(secret.Reference) != "" {
		line += "  " + setupStyle(out, "2", "("+secret.Reference+")")
	}
	return line
}

func setupSummaryAppLine(out io.Writer, app setupAppOutcome) string {
	line := "  " + setupStyle(out, "1;32", cliGlyph(out, "•", "-")) + " " +
		setupSummaryLabel(out, fmt.Sprintf("%-18s", app.Name))
	if strings.TrimSpace(app.LauncherPath) != "" {
		line += "  " + setupSummaryValue(out, app.LauncherPath)
	}
	if strings.TrimSpace(app.ProjectRoot) != "" {
		line += "  " + setupStyle(out, "2", "("+app.ProjectRoot+")")
	}
	if app.PathUpdate.Changed {
		line += "  " + setupStyle(out, "2", "(PATH updated)")
	}
	return line
}

func setupSummaryStepLine(out io.Writer, index int, step string) string {
	return "  " + setupStyle(out, "1;36", fmt.Sprintf("%d.", index)) + " " + step
}

func setupStyle(out io.Writer, code string, text string) string {
	if !setupWriterSupportsColor(out) {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func setupSplitNumericPrefix(line string) (string, string, bool) {
	for _, prefix := range []string{"10.", "9.", "8.", "7.", "6.", "5.", "4.", "3.", "2.", "1."} {
		if strings.HasPrefix(line, prefix+" ") {
			return prefix, strings.TrimPrefix(line, prefix+" "), true
		}
	}
	return "", "", false
}

func setupWriteSelectedAgents(out io.Writer, agents []setupAgentSpec) error {
	if len(agents) == 0 {
		return nil
	}
	lines := make([]string, 0, len(agents)+1)
	lines = append(lines, "Selected agent config targets:")
	for _, agent := range agents {
		lines = append(lines, fmt.Sprintf("- %s -> %s", agent.Label, agent.ConfigPath("")))
	}
	return setupWriteStage(out, "Agent targets", lines...)
}

func setupWriteAgentMenu(out io.Writer, supported []setupAgentSpec, defaultIDs []string) error {
	lines := []string{
		"Pick which coding agents HASP should configure for MCP.",
		"Enter numbers like 1 or 1,3. Enter 0 to skip agent setup for now.",
		"Existing config files are backed up before mutation.",
	}
	defaultSet := map[string]struct{}{}
	for _, id := range defaultIDs {
		defaultSet[id] = struct{}{}
	}
	for idx, agent := range supported {
		suffix := ""
		if _, ok := defaultSet[agent.ID]; ok {
			suffix = " [detected]"
		}
		lines = append(lines, fmt.Sprintf("%d. %s%s", idx+1, agent.Label, suffix))
		lines = append(lines, fmt.Sprintf("   config: %s", setupDisplayPath(agent.ConfigPath(""))))
	}
	return setupWriteStage(out, "Agent setup", lines...)
}

func setupDefaultAgentIDs(detected []setupAgentSpec) []string {
	defaultIDs := make([]string, 0, len(detected))
	for _, spec := range detected {
		defaultIDs = append(defaultIDs, spec.ID)
	}
	if len(defaultIDs) == 0 {
		defaultIDs = []string{"codex-cli"}
	}
	return defaultIDs
}

func setupDefaultAgentSelection(supported []setupAgentSpec, defaultIDs []string) string {
	indexes := make([]string, 0, len(defaultIDs))
	for _, id := range defaultIDs {
		for idx, spec := range supported {
			if spec.ID == id {
				indexes = append(indexes, strconv.Itoa(idx+1))
				break
			}
		}
	}
	if len(indexes) == 0 {
		return "0"
	}
	return strings.Join(indexes, ",")
}

func parseSetupAgentMenuSelection(supported []setupAgentSpec, value string) ([]string, error) {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" || trimmed == "0" || trimmed == "skip" || trimmed == "none" {
		return nil, nil
	}
	selected := []string{}
	seen := map[string]struct{}{}
	for _, raw := range strings.Split(value, ",") {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		if index, err := strconv.Atoi(token); err == nil {
			if index < 1 || index > len(supported) {
				return nil, fmt.Errorf("unsupported setup agent selection %q", token)
			}
			id := supported[index-1].ID
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			selected = append(selected, id)
			continue
		}
		idx := slices.IndexFunc(supported, func(spec setupAgentSpec) bool { return spec.ID == token })
		if idx < 0 {
			return nil, fmt.Errorf("unsupported setup agent selection %q", token)
		}
		id := supported[idx].ID
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		selected = append(selected, id)
	}
	return selected, nil
}

func setupWriteConfirmation(out io.Writer, plan setupPlanPreview) error {
	if _, err := fmt.Fprintln(out, setupStageHeader(out, "Review before apply")); err != nil {
		return err
	}
	lines := []string{
		setupSummaryKeyValue(out, "Local HASP data", setupDisplayPath(plan.HaspHome)),
		setupSummaryKeyValue(out, "Automatic repo adoption", setupEnabledDisabled(plan.AutoProtectRepos)),
		setupSummaryKeyValue(out, "Install repo guardrails", setupYesNo(plan.InstallHooks)),
		setupSummaryKeyValue(out, "Convenience unlock", setupEnabledDisabled(plan.EnableConvenienceUnlock)),
	}
	if strings.TrimSpace(plan.ProjectRoot) != "" {
		lines = append(lines, setupSummaryKeyValue(out, "Protect this repo now", plan.ProjectRoot))
	}
	if strings.TrimSpace(plan.ImportPath) == "" {
		lines = append(lines, setupSummaryKeyValue(out, "Import during setup", "skip for now"))
	} else {
		lines = append(lines, setupSummaryKeyValue(out, "Import during setup", plan.ImportPath))
		lines = append(lines, setupSummaryKeyValue(out, "Bind imported secrets", setupYesNo(plan.BindImports)))
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	if plan.ConfigExists {
		if _, err := fmt.Fprintln(out, setupStageLine(out, "Existing agent config files will be updated with backups.")); err != nil {
			return err
		}
	}
	if len(plan.Agents) > 0 {
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
		if err := setupWriteSummarySection(out, "Agent config targets"); err != nil {
			return err
		}
		bullet := cliGlyph(out, "•", "-")
		for _, agent := range plan.Agents {
			if _, err := fmt.Fprintln(out, "  "+setupStyle(out, "1;36", bullet)+" "+setupSummaryLabel(out, fmt.Sprintf("%-18s", agent.Label))+"  "+setupSummaryValue(out, setupDisplayPath(agent.ConfigPath("")))); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintln(out); err != nil {
		return err
	}
	return nil
}

func setupConfirmPlan(prompt *setupPrompter, plan setupPlanPreview) error {
	if err := setupWriteConfirmationFn(prompt.out, plan); err != nil {
		return err
	}
	proceed, err := promptBool(prompt, "Apply these changes now", true)
	if err != nil {
		return err
	}
	if !proceed {
		return errors.New("setup cancelled before making changes")
	}
	return nil
}

func setupDisplayPath(path string) string {
	home, err := setupUserHomeDirFn()
	if err != nil {
		return path
	}
	if path == home {
		return "~"
	}
	prefix := home + string(filepath.Separator)
	if strings.HasPrefix(path, prefix) {
		return "~" + string(filepath.Separator) + strings.TrimPrefix(path, prefix)
	}
	return path
}

func setupYesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func setupEnabledDisabled(value bool) string {
	if value {
		return "enabled when available"
	}
	return "disabled"
}

func promptString(prompt *setupPrompter, label string, defaultValue string) (string, error) {
	return promptStringWithDisplayDefault(prompt, label, defaultValue, defaultValue)
}

func promptStringWithDisplayDefault(prompt *setupPrompter, label string, defaultValue string, displayDefault string) (string, error) {
	if defaultValue != "" {
		if _, err := fmt.Fprintf(prompt.out, "%s [%s]: ", label, displayDefault); err != nil {
			return "", err
		}
	} else {
		if _, err := fmt.Fprintf(prompt.out, "%s: ", label); err != nil {
			return "", err
		}
	}
	line, err := prompt.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if _, err := fmt.Fprintln(prompt.out); err != nil {
		return "", err
	}
	value := strings.TrimSpace(line)
	if value == "" {
		return defaultValue, nil
	}
	return value, nil
}

func promptBool(prompt *setupPrompter, label string, defaultValue bool) (bool, error) {
	defaultLabel := "y/N"
	if defaultValue {
		defaultLabel = "Y/n"
	}
	value, err := promptString(prompt, label, defaultLabel)
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "", strings.ToLower(defaultLabel):
		return defaultValue, nil
	case "y", "yes", "true", "1":
		return true, nil
	case "n", "no", "false", "0":
		return false, nil
	default:
		return defaultValue, nil
	}
}

func promptPassword(prompt *setupPrompter, label string) (string, error) {
	if prompt.file == nil || !setupCanHideInputFn(prompt.file) {
		return promptString(prompt, label+" (input is visible)", "")
	}
	if _, err := fmt.Fprintf(prompt.out, "%s: ", label); err != nil {
		return "", err
	}
	if err := setupSttyFn(prompt.file, "-echo"); err != nil {
		return promptString(prompt, label+" (input is visible)", "")
	}
	defer func() {
		_ = setupSttyFn(prompt.file, "echo")
		_, _ = fmt.Fprintln(prompt.out)
	}()
	line, err := prompt.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
