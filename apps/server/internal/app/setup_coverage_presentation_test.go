package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupPresentationHelpers(t *testing.T) {
	t.Run("prompt string with display default", func(t *testing.T) {
		lockAppSeams(t)
		var out bytes.Buffer
		value, err := promptStringWithDisplayDefault(newSetupPrompter(bytes.NewBufferString("\n"), &out), "label", "/Users/tester/.hasp", "~/.hasp")
		if err != nil || value != "/Users/tester/.hasp" {
			t.Fatalf("unexpected value=%q err=%v", value, err)
		}
		if !strings.Contains(out.String(), "[~/.hasp]") {
			t.Fatalf("expected display default in output, got %q", out.String())
		}
	})

	t.Run("display path and convenience defaults", func(t *testing.T) {
		lockAppSeams(t)
		origHome := setupUserHomeDirFn
		origGOOS := setupGOOS
		origTempDir := setupTempDirFn
		origAbs := setupAbsFn
		defer func() {
			setupUserHomeDirFn = origHome
			setupGOOS = origGOOS
			setupTempDirFn = origTempDir
			setupAbsFn = origAbs
		}()
		setupUserHomeDirFn = func() (string, error) { return "/Users/tester", nil }
		if got := setupDisplayPath("/Users/tester"); got != "~" {
			t.Fatalf("unexpected home display path %q", got)
		}
		if got := setupDisplayPath("/Users/tester/.hasp"); got != "~/.hasp" {
			t.Fatalf("unexpected display path %q", got)
		}
		setupUserHomeDirFn = func() (string, error) { return "", errors.New("home fail") }
		if got := setupDisplayPath("/tmp/custom"); got != "/tmp/custom" {
			t.Fatalf("unexpected fallback display path %q", got)
		}
		setupUserHomeDirFn = func() (string, error) { return "/Users/tester", nil }
		if got := setupDisplayPath("/tmp/custom"); got != "/tmp/custom" {
			t.Fatalf("unexpected non-home display path %q", got)
		}
		setupGOOS = "darwin"
		if !defaultSetupConvenienceUnlock() {
			t.Fatal("expected darwin default convenience unlock")
		}
		setupGOOS = "linux"
		if defaultSetupConvenienceUnlock() {
			t.Fatal("expected non-darwin default convenience unlock false")
		}
		tempSaved := t.TempDir()
		setupTempDirFn = func() string { return filepath.Join(t.TempDir(), "elsewhere") }
		if !setupSavedHomeLooksUsable(tempSaved) {
			t.Fatal("expected non-temp-root saved path to be accepted")
		}
		setupTempDirFn = func() string { return filepath.Dir(tempSaved) }
		if setupSavedHomeLooksUsable(tempSaved) {
			t.Fatal("expected temp-root saved path to be rejected")
		}
		if setupSavedHomeLooksUsable(filepath.Join(t.TempDir(), "missing")) {
			t.Fatal("expected missing saved path to be rejected")
		}
		if setupSavedHomeLooksUsable("   ") {
			t.Fatal("expected blank saved path to be rejected")
		}
		parentFile := filepath.Join(t.TempDir(), "parent")
		if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
			t.Fatalf("write parent file: %v", err)
		}
		if setupSavedHomeLooksUsable(filepath.Join(parentFile, "child")) {
			t.Fatal("expected stat error path to be rejected")
		}
		setupTempDirFn = func() string { return "" }
		if !setupSavedHomeLooksUsable(tempSaved) {
			t.Fatal("expected empty temp root to accept saved path")
		}
		setupTempDirFn = func() string { return filepath.Dir(tempSaved) }
		setupAbsFn = func(string) (string, error) { return "", errors.New("abs fail") }
		if setupSavedHomeLooksUsable(tempSaved) {
			t.Fatal("expected abs failure to reject saved path")
		}
		callCount := 0
		setupAbsFn = func(value string) (string, error) {
			callCount++
			if callCount == 1 {
				return value, nil
			}
			return "", errors.New("abs temp fail")
		}
		if setupSavedHomeLooksUsable(tempSaved) {
			t.Fatal("expected temp-root abs failure to reject saved path")
		}
	})

	t.Run("stage and summary writers", func(t *testing.T) {
		lockAppSeams(t)
		var out bytes.Buffer
		if err := setupWriteIntro(&out); err != nil {
			t.Fatalf("write intro: %v", err)
		}
		if err := setupWriteAgentMenu(&out, []setupAgentSpec{
			{ID: "codex-cli", Label: "Codex CLI", ConfigPath: func(string) string { return "/tmp/codex.toml" }},
			{ID: "cursor", Label: "Cursor", ConfigPath: func(string) string { return "/tmp/cursor.json" }},
		}, []string{"cursor"}); err != nil {
			t.Fatalf("write agent menu: %v", err)
		}
		if err := setupWriteSelectedAgents(&out, []setupAgentSpec{{ID: "codex-cli", Label: "Codex CLI", ConfigPath: func(string) string { return "/tmp/codex.toml" }}}); err != nil {
			t.Fatalf("write selected agents: %v", err)
		}
		if err := setupWriteConfirmation(&out, setupPlanPreview{
			HaspHome:                "/tmp/.hasp",
			ProjectRoot:             "/tmp/repo",
			Agents:                  []setupAgentSpec{{ID: "codex-cli", Label: "Codex CLI", ConfigPath: func(string) string { return "/tmp/codex.toml" }}},
			ImportPath:              "/tmp/.env",
			BindImports:             true,
			InstallHooks:            true,
			EnableConvenienceUnlock: true,
			ConfigExists:            true,
		}); err != nil {
			t.Fatalf("write confirmation: %v", err)
		}
		if err := renderSetupSummary(&out, setupSummary{
			HaspHome:          "/tmp/.hasp",
			ConfigPath:        "/tmp/hasp-cli.json",
			InitState:         "created",
			ProjectRoot:       "/tmp/repo",
			ConvenienceUnlock: "enabled",
			AddedSecrets: []secretMutationView{{
				Name:    "API_TOKEN",
				Outcome: "created",
			}},
			Apps: []setupAppOutcome{{
				Name:         "myapp",
				LauncherPath: "/tmp/.hasp/bin/myapp",
				PathUpdate:   appPathUpdateResult{Changed: true},
			}},
			Agents: []setupAgentOutcome{{
				Label:      "Codex CLI",
				ConfigPath: "/tmp/codex.toml",
				Changed:    true,
			}},
			NextSteps: []string{"next"},
		}); err != nil {
			t.Fatalf("render summary: %v", err)
		}
		text := out.String()
		if !strings.Contains(text, "HASP setup") || !strings.Contains(text, "Setup complete") || !strings.Contains(text, "Configured agents") || !strings.Contains(text, "Review before apply") {
			t.Fatalf("unexpected presentation output %q", text)
		}
		if !strings.Contains(text, "  • HASP setup will:") {
			t.Fatalf("expected bulleted intro line, got %q", text)
		}
		if !strings.Contains(text, "  1. choose where local encrypted HASP data lives on this machine") {
			t.Fatalf("expected numbered intro step to stay numbered, got %q", text)
		}
		if !strings.Contains(text, "  3. optionally configure coding agents, add vault secrets, and connect one app\n  4. verify the local broker path and surface a first proof command when a bound secret is available\n\n  • Press Enter to accept the default shown in brackets.") {
			t.Fatalf("expected spacing between numbered intro list and trailing prose, got %q", text)
		}
		if !strings.Contains(text, "  • Enter numbers like 1 or 1,3. Enter 0 to skip agent setup for now.\n  • Existing config files are backed up before mutation.\n\n  1. Codex CLI") {
			t.Fatalf("expected spacing between agent prose and numbered list, got %q", text)
		}
		if !strings.Contains(text, "\n✓ HASP is configured for this machine.\n") {
			t.Fatalf("expected summary lead without stage indentation, got %q", text)
		}
		if strings.Contains(text, "\n  HASP is configured for this machine.\n") {
			t.Fatalf("expected summary lead indentation bug to stay fixed, got %q", text)
		}
		if !strings.Contains(text, "\nMachine\n") || !strings.Contains(text, "\nDefaults\n") || !strings.Contains(text, "\nAdded secrets\n") || !strings.Contains(text, "\nConnected apps\n") || !strings.Contains(text, "\nNext steps\n") {
			t.Fatalf("expected grouped summary sections, got %q", text)
		}
		if !strings.Contains(text, "Local HASP data") || !strings.Contains(text, "Automatic repo adoption") {
			t.Fatalf("expected aligned summary key/value rows, got %q", text)
		}
		if !strings.Contains(text, "1. next") {
			t.Fatalf("expected numbered next step, got %q", text)
		}

		countWriter := &setupCountWriter{}
		if err := renderSetupSummary(countWriter, setupSummary{
			HaspHome:          "/tmp/.hasp",
			ConfigPath:        "/tmp/hasp-cli.json",
			InitState:         "created",
			ProjectRoot:       "/tmp/repo",
			ConvenienceUnlock: "enabled",
			Verification: map[string]any{
				"mcp":            map[string]any{"ready": true},
				"brokered_proof": map[string]any{"performed": true, "reference": "@API_TOKEN"},
			},
			Agents: []setupAgentOutcome{{
				Label:      "Codex CLI",
				ConfigPath: "/tmp/codex.toml",
				Changed:    true,
			}},
			NextSteps: []string{"next"},
		}); err != nil {
			t.Fatalf("count render summary: %v", err)
		}
		for failAt := 1; failAt <= countWriter.writes; failAt++ {
			writer := &setupNthWriteErrWriter{allow: failAt - 1, err: errors.New("write fail")}
			err := renderSetupSummary(writer, setupSummary{
				HaspHome:          "/tmp/.hasp",
				ConfigPath:        "/tmp/hasp-cli.json",
				InitState:         "created",
				ProjectRoot:       "/tmp/repo",
				ConvenienceUnlock: "enabled",
				Verification: map[string]any{
					"mcp":            map[string]any{"ready": true},
					"brokered_proof": map[string]any{"performed": true, "reference": "@API_TOKEN"},
				},
				Agents: []setupAgentOutcome{{
					Label:      "Codex CLI",
					ConfigPath: "/tmp/codex.toml",
					Changed:    true,
				}},
				NextSteps: []string{"next"},
			})
			if err == nil {
				t.Fatalf("expected render summary write failure at call %d", failAt)
			}
		}

		countWriter = &setupCountWriter{}
		if err := setupWriteConfirmation(countWriter, setupPlanPreview{
			HaspHome:                "/tmp/.hasp",
			ProjectRoot:             "/tmp/repo",
			Agents:                  []setupAgentSpec{{ID: "codex-cli", Label: "Codex CLI", ConfigPath: func(string) string { return "/tmp/codex.toml" }}},
			InstallHooks:            true,
			EnableConvenienceUnlock: true,
		}); err != nil {
			t.Fatalf("count write confirmation: %v", err)
		}
		for failAt := 1; failAt <= countWriter.writes; failAt++ {
			writer := &setupNthWriteErrWriter{allow: failAt - 1, err: errors.New("write fail")}
			if err := setupWriteConfirmation(writer, setupPlanPreview{
				HaspHome:                "/tmp/.hasp",
				ProjectRoot:             "/tmp/repo",
				Agents:                  []setupAgentSpec{{ID: "codex-cli", Label: "Codex CLI", ConfigPath: func(string) string { return "/tmp/codex.toml" }}},
				InstallHooks:            true,
				EnableConvenienceUnlock: true,
			}); err == nil {
				t.Fatalf("expected write confirmation failure at call %d", failAt)
			}
		}
		out.Reset()
		if err := renderSetupSummary(&out, setupSummary{
			HaspHome:          "/tmp/.hasp",
			ConfigPath:        "/tmp/hasp-cli.json",
			InitState:         "created",
			ProjectRoot:       "/tmp/repo",
			ConvenienceUnlock: "enabled",
			Agents: []setupAgentOutcome{{
				Label:      "Codex CLI",
				ConfigPath: "/tmp/codex.toml",
				Changed:    false,
			}},
		}); err != nil {
			t.Fatalf("render summary unchanged agent: %v", err)
		}
		if !strings.Contains(out.String(), "(unchanged)") {
			t.Fatalf("expected unchanged agent suffix, got %q", out.String())
		}

		out.Reset()
		if err := setupWriteConfirmation(&out, setupPlanPreview{
			HaspHome:                "/tmp/.hasp",
			ImportPath:              "/tmp/.env",
			BindImports:             true,
			AutoProtectRepos:        false,
			InstallHooks:            false,
			EnableConvenienceUnlock: false,
		}); err != nil {
			t.Fatalf("write confirmation with import preview: %v", err)
		}
		if !strings.Contains(out.String(), "Import during setup") || !strings.Contains(out.String(), "Bind imported secrets") {
			t.Fatalf("expected confirmation import details, got %q", out.String())
		}
	})

	t.Run("setup command json and human output modes", func(t *testing.T) {
		lockAppSeams(t)
		userHome := t.TempDir()
		haspHome := filepath.Join(t.TempDir(), "hasp-home")
		repo := t.TempDir()
		t.Setenv("HOME", userHome)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(userHome, ".config"))
		t.Setenv("SETUP_MASTER_PASSWORD", "correct horse battery staple")

		origHome := setupUserHomeDirFn
		origLookPath := setupLookPathFn
		defer func() {
			setupUserHomeDirFn = origHome
			setupLookPathFn = origLookPath
		}()
		setupUserHomeDirFn = func() (string, error) { return userHome, nil }
		setupLookPathFn = func(string) (string, error) { return "", os.ErrNotExist }

		var stdout bytes.Buffer
		if err := setupCommand(context.Background(), []string{
			"--non-interactive",
			"--json",
			"--hasp-home", haspHome,
			"--repo", repo,
			"--agent", "codex-cli",
			"--master-password-env", "SETUP_MASTER_PASSWORD",
			"--install-hooks=false",
			"--enable-convenience-unlock=false",
			"--overwrite-existing-config=true",
		}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
			t.Fatalf("setup command json mode: %v", err)
		}
		if !json.Valid(stdout.Bytes()) {
			t.Fatalf("expected json output, got %q", stdout.String())
		}
	})

	t.Run("stage writers and prompt bool branches", func(t *testing.T) {
		lockAppSeams(t)
		if err := setupWriteSelectedAgents(io.Discard, nil); err != nil {
			t.Fatalf("expected empty selected agents writer to succeed, got %v", err)
		}
		if got := setupDefaultAgentIDs(nil); len(got) != 1 || got[0] != "codex-cli" {
			t.Fatalf("unexpected default agent ids %+v", got)
		}
		if got := setupDefaultAgentSelection([]setupAgentSpec{{ID: "codex-cli"}, {ID: "cursor"}}, []string{"cursor"}); got != "2" {
			t.Fatalf("unexpected default agent selection %q", got)
		}
		if got := setupDefaultAgentSelection([]setupAgentSpec{{ID: "codex-cli"}}, []string{"missing"}); got != "0" {
			t.Fatalf("unexpected fallback default agent selection %q", got)
		}
		selection, err := parseSetupAgentMenuSelection([]setupAgentSpec{{ID: "codex-cli"}}, "0")
		if err != nil || len(selection) != 0 {
			t.Fatalf("unexpected parsed skip selection %+v err=%v", selection, err)
		}
		selection, err = parseSetupAgentMenuSelection([]setupAgentSpec{{ID: "codex-cli"}}, "skip")
		if err != nil || len(selection) != 0 {
			t.Fatalf("unexpected parsed skip token %+v err=%v", selection, err)
		}
		selection, err = parseSetupAgentMenuSelection([]setupAgentSpec{{ID: "codex-cli"}, {ID: "cursor"}}, "2,codex-cli,2")
		if err != nil || len(selection) != 2 || selection[0] != "cursor" || selection[1] != "codex-cli" {
			t.Fatalf("unexpected parsed selection %+v err=%v", selection, err)
		}
		selection, err = parseSetupAgentMenuSelection([]setupAgentSpec{{ID: "codex-cli"}, {ID: "cursor"}}, " , cursor , ")
		if err != nil || len(selection) != 1 || selection[0] != "cursor" {
			t.Fatalf("unexpected parsed selection with blanks %+v err=%v", selection, err)
		}
		selection, err = parseSetupAgentMenuSelection([]setupAgentSpec{{ID: "codex-cli"}, {ID: "cursor"}}, "cursor,cursor")
		if err != nil || len(selection) != 1 || selection[0] != "cursor" {
			t.Fatalf("unexpected parsed duplicate id selection %+v err=%v", selection, err)
		}
		if _, err := parseSetupAgentMenuSelection([]setupAgentSpec{{ID: "codex-cli"}}, "9"); err == nil {
			t.Fatal("expected invalid menu selection error")
		}
		if _, err := parseSetupAgentMenuSelection([]setupAgentSpec{{ID: "codex-cli"}}, "missing"); err == nil {
			t.Fatal("expected invalid menu token error")
		}
		if setupYesNo(true) != "yes" || setupYesNo(false) != "no" {
			t.Fatal("unexpected yes/no formatting")
		}
		if setupEnabledDisabled(true) != "enabled when available" || setupEnabledDisabled(false) != "disabled" {
			t.Fatal("unexpected enabled/disabled formatting")
		}
		for failAt := 1; failAt <= 3; failAt++ {
			writer := &setupNthWriteErrWriter{allow: failAt - 1, err: errors.New("write fail")}
			if err := setupWriteStage(writer, "Title", "line"); err == nil {
				t.Fatalf("expected setupWriteStage failure at call %d", failAt)
			}
		}
		writer := &setupNthWriteErrWriter{allow: 2, err: errors.New("separator fail")}
		if err := setupWriteStage(writer, "Title", "explanation", "1. step"); err == nil {
			t.Fatal("expected setupWriteStage separator failure")
		}
		writer = &setupNthWriteErrWriter{allow: 0, err: errors.New("write fail")}
		if err := setupWriteSelectedAgents(writer, []setupAgentSpec{{Label: "Codex CLI", ConfigPath: func(string) string { return "/tmp/codex.toml" }}}); err == nil {
			t.Fatal("expected setupWriteSelectedAgents failure")
		}
		writer = &setupNthWriteErrWriter{allow: 0, err: errors.New("write fail")}
		if err := setupWriteAgentMenu(writer, []setupAgentSpec{{Label: "Codex CLI", ConfigPath: func(string) string { return "/tmp/codex.toml" }}}, []string{"codex-cli"}); err == nil {
			t.Fatal("expected setupWriteAgentMenu failure")
		}
		if value, err := promptBool(newSetupPrompter(bytes.NewBufferString("\n"), io.Discard), "label", true); err != nil || !value {
			t.Fatalf("expected blank promptBool to use default true, got %v err=%v", value, err)
		}
	})
}
