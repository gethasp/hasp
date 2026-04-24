package app

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupUIHelpersDirect(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	origHome := setupUserHomeDirFn
	defer func() { setupUserHomeDirFn = origHome }()
	setupUserHomeDirFn = func() (string, error) { return homeDir, nil }

	summary := setupSummary{
		HaspHome:          filepath.Join(homeDir, ".hasp"),
		ConfigPath:        filepath.Join(homeDir, ".config", "hasp.json"),
		InitState:         "created",
		ProjectRoot:       filepath.Join(homeDir, "repo"),
		AutoProtectRepos:  true,
		AutoInstallHooks:  true,
		ConvenienceUnlock: "enabled",
		ConvenienceDetail: "ok",
		Agents:            []setupAgentOutcome{{ID: "claude-code", Label: "Claude Code", ConfigPath: filepath.Join(homeDir, ".claude.json"), Changed: true}},
		AddedSecrets:      []secretMutationView{{Name: "API_TOKEN", Outcome: "created", Reference: "secret_01"}},
		Apps:              []setupAppOutcome{{Name: "myapp", ProjectRoot: filepath.Join(homeDir, "repo"), LauncherPath: filepath.Join(homeDir, "bin", "myapp"), PathUpdate: appPathUpdateResult{Changed: true}}},
		Verification: map[string]any{
			"mcp":            map[string]any{"ready": true},
			"brokered_proof": map[string]any{"performed": true, "reference": "@API_TOKEN"},
		},
		NextSteps: []string{"next one", "next two"},
	}
	var out bytes.Buffer
	if err := renderSetupSummary(&out, summary); err != nil {
		t.Fatalf("renderSetupSummary: %v", err)
	}
	if !strings.Contains(out.String(), "Setup complete") || !strings.Contains(out.String(), "Configured agents") || !strings.Contains(out.String(), "Verification") {
		t.Fatalf("unexpected setup summary %q", out.String())
	}

	out.Reset()
	if err := setupWriteIntro(&out); err != nil {
		t.Fatalf("setupWriteIntro: %v", err)
	}
	if err := setupWriteStage(&out, "Stage", "1. first", "plain text", "   config: ~/.claude.json", "   indented", "- dash"); err != nil {
		t.Fatalf("setupWriteStage: %v", err)
	}
	if !strings.Contains(out.String(), "Stage") {
		t.Fatalf("expected stage output, got %q", out.String())
	}

	if got := setupStageLine(&out, "1. item"); !strings.Contains(got, "1.") {
		t.Fatalf("setupStageLine numeric = %q", got)
	}
	if got := setupStageLine(&out, "   config: /tmp/x"); !strings.Contains(got, "config") {
		t.Fatalf("setupStageLine config = %q", got)
	}
	if got := setupStageLine(&out, "   indented"); got != "   indented" {
		t.Fatalf("setupStageLine indented = %q", got)
	}
	if got := setupStageLine(&out, "plain"); !strings.Contains(got, "plain") {
		t.Fatalf("setupStageLine plain = %q", got)
	}
	if !setupShouldSeparateStageLines("1. item", "plain") || !setupShouldSeparateStageLines("plain:", "1. item") == false {
		t.Fatal("unexpected setupShouldSeparateStageLines result")
	}
	if kind := setupStageLineKind("   config: x"); kind != "config" {
		t.Fatalf("setupStageLineKind config = %q", kind)
	}
	if kind := setupStageLineKind("1. item"); kind != "numeric" {
		t.Fatalf("setupStageLineKind numeric = %q", kind)
	}
	if kind := setupStageLineKind("- item"); kind != "dash" {
		t.Fatalf("setupStageLineKind dash = %q", kind)
	}
	if kind := setupStageLineKind("   x"); kind != "indented" {
		t.Fatalf("setupStageLineKind indented = %q", kind)
	}

	if setupWriterSupportsColor(&out) {
		t.Fatal("expected bytes buffer to disable color")
	}
	if setupSummaryLead(&out, "ok") == "" || setupSummarySectionHeader(&out, "Title") == "" || setupSummaryLabel(&out, "Name") == "" {
		t.Fatal("expected styled setup helpers")
	}
	if got := setupSummaryValue(&out, "enabled"); got == "" {
		t.Fatal("expected summary value")
	}
	if got := setupSummaryAgentLine(&out, setupAgentOutcome{Label: "Claude", ConfigPath: "/tmp/.claude.json", Changed: false}); !strings.Contains(got, "unchanged") {
		t.Fatalf("setupSummaryAgentLine = %q", got)
	}
	if got := setupSummarySecretLine(&out, secretMutationView{Name: "API_TOKEN", Outcome: "created"}); !strings.Contains(got, "created") {
		t.Fatalf("setupSummarySecretLine = %q", got)
	}
	if got := setupSummaryAppLine(&out, setupAppOutcome{Name: "myapp", ProjectRoot: "/tmp/repo", LauncherPath: "/tmp/bin/myapp", PathUpdate: appPathUpdateResult{Changed: true}}); !strings.Contains(got, "PATH updated") {
		t.Fatalf("setupSummaryAppLine = %q", got)
	}
	if got := setupSummaryStepLine(&out, 2, "step"); !strings.Contains(got, "2.") {
		t.Fatalf("setupSummaryStepLine = %q", got)
	}
	if got := setupStyle(&out, "1;32", "text"); got == "" {
		t.Fatal("expected setupStyle output")
	}
	if prefix, rest, ok := setupSplitNumericPrefix("10. ten"); !ok || prefix != "10." || rest != "ten" {
		t.Fatalf("setupSplitNumericPrefix = %q %q %v", prefix, rest, ok)
	}

	out.Reset()
	if err := renderSetupSummary(&out, setupSummary{
		HaspHome:   filepath.Join(homeDir, ".hasp"),
		ConfigPath: filepath.Join(homeDir, ".config", "hasp.json"),
		InitState:  "existing",
		Verification: map[string]any{
			"mcp":            map[string]any{"ready": false},
			"brokered_proof": map[string]any{"performed": false, "reason": "no brokered reference available yet"},
		},
	}); err != nil {
		t.Fatalf("renderSetupSummary skipped proof: %v", err)
	}
	if !strings.Contains(out.String(), "not-ready") || !strings.Contains(out.String(), "unavailable") || !strings.Contains(out.String(), "no brokered reference available yet") {
		t.Fatalf("expected skipped verification states, got %q", out.String())
	}

	out.Reset()
	agents := []setupAgentSpec{{ID: "codex-cli", Label: "Codex CLI", ConfigPath: func(string) string { return filepath.Join(homeDir, ".codex", "config.toml") }}}
	if err := setupWriteSelectedAgents(&out, agents); err != nil {
		t.Fatalf("setupWriteSelectedAgents: %v", err)
	}
	if err := setupWriteAgentMenu(&out, agents, []string{"codex-cli"}); err != nil {
		t.Fatalf("setupWriteAgentMenu: %v", err)
	}
	if got := setupDefaultAgentIDs(nil); len(got) != 1 || got[0] != "codex-cli" {
		t.Fatalf("setupDefaultAgentIDs default = %+v", got)
	}
	if got := setupDefaultAgentSelection(agents, []string{"codex-cli"}); got != "1" {
		t.Fatalf("setupDefaultAgentSelection = %q", got)
	}
	selected, err := parseSetupAgentMenuSelection(append(agents, setupAgentSpec{ID: "claude-code"}), "1,claude-code,1")
	if err != nil || len(selected) != 2 {
		t.Fatalf("parseSetupAgentMenuSelection = %+v err=%v", selected, err)
	}
	if _, err := parseSetupAgentMenuSelection(agents, "bad"); err == nil {
		t.Fatal("expected bad selection error")
	}

	out.Reset()
	if err := setupWriteConfirmation(&out, setupPlanPreview{
		HaspHome:                filepath.Join(homeDir, ".hasp"),
		ProjectRoot:             filepath.Join(homeDir, "repo"),
		Agents:                  agents,
		AutoProtectRepos:        true,
		InstallHooks:            true,
		EnableConvenienceUnlock: true,
		ConfigExists:            true,
	}); err != nil {
		t.Fatalf("setupWriteConfirmation: %v", err)
	}
	if err := setupConfirmPlan(newSetupPrompter(bytes.NewBufferString("y\n"), &out), setupPlanPreview{}); err != nil {
		t.Fatalf("setupConfirmPlan yes: %v", err)
	}
	if err := setupConfirmPlan(newSetupPrompter(bytes.NewBufferString("n\n"), &out), setupPlanPreview{}); err == nil {
		t.Fatal("expected setupConfirmPlan cancellation")
	}

	if got := setupDisplayPath(homeDir); got != "~" {
		t.Fatalf("setupDisplayPath home = %q", got)
	}
	if got := setupYesNo(true); got != "yes" || setupEnabledDisabled(false) != "disabled" {
		t.Fatal("unexpected yes/no helpers")
	}
	if value, err := promptString(newSetupPrompter(bytes.NewBufferString("\n"), &out), "Label", "default"); err != nil || value != "default" {
		t.Fatalf("promptString default = %q err=%v", value, err)
	}
	if value, err := promptStringWithDisplayDefault(newSetupPrompter(bytes.NewBufferString("custom\n"), &out), "Label", "default", "~/.hasp"); err != nil || value != "custom" {
		t.Fatalf("promptStringWithDisplayDefault = %q err=%v", value, err)
	}
	if value, err := promptBool(newSetupPrompter(bytes.NewBufferString("bogus\n"), &out), "Label", true); err != nil || !value {
		t.Fatalf("promptBool fallback = %v err=%v", value, err)
	}
	if value, err := promptPassword(newSetupPrompter(bytes.NewBufferString("visible\n"), &out), "Password"); err != nil || value != "visible" {
		t.Fatalf("promptPassword visible = %q err=%v", value, err)
	}

	tempFile, err := os.CreateTemp(t.TempDir(), "prompt-pass")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer tempFile.Close()
	if _, err := tempFile.WriteString("hidden\n"); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if _, err := tempFile.Seek(0, 0); err != nil {
		t.Fatalf("seek temp file: %v", err)
	}
	origCanHide := setupCanHideInputFn
	origStty := setupSttyFn
	defer func() {
		setupCanHideInputFn = origCanHide
		setupSttyFn = origStty
	}()
	setupCanHideInputFn = func(*os.File) bool { return true }
	setupSttyFn = func(*os.File, ...string) error { return nil }
	prompt := &setupPrompter{reader: bufio.NewReader(tempFile), out: &out, file: tempFile}
	if value, err := promptPassword(prompt, "Password"); err != nil || value != "hidden" {
		t.Fatalf("promptPassword hidden = %q err=%v", value, err)
	}

	if err := setupWriteKeyValueBlock(errWriter{err: errors.New("write fail")}, "Title", "line"); err == nil {
		t.Fatal("expected setupWriteKeyValueBlock failure")
	}
}
