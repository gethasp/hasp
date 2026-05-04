package app

import (
	"bytes"
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/quick"

	"github.com/creack/pty"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestSetupNewVaultPasswordContractNeverExitsOnEmptyInput(t *testing.T) {
	lockAppSeams(t)

	cfg := &quick.Config{
		MaxCount: 64,
		Rand:     rand.New(rand.NewSource(1)),
	}
	property := func(raw uint8) bool {
		emptyEntries := int(raw % 32)
		var input strings.Builder
		for range emptyEntries {
			input.WriteString("\n")
		}
		input.WriteString("correct horse battery staple\n")
		input.WriteString("correct horse battery staple\n")

		var out bytes.Buffer
		password, exists, err := setupResolvePassword(newSetupPrompter(strings.NewReader(input.String()), &out), setupOptions{}, t.TempDir())
		if err != nil || exists || password != "correct horse battery staple" {
			t.Logf("emptyEntries=%d password=%q exists=%v err=%v output=%q", emptyEntries, password, exists, err, out.String())
			return false
		}
		retries := strings.Count(out.String(), "Master password is required. Try again.")
		if retries != emptyEntries {
			t.Logf("emptyEntries=%d retries=%d output=%q", emptyEntries, retries, out.String())
			return false
		}
		return true
	}
	if err := quick.Check(property, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestSetupNewVaultPasswordContractRetriesEveryRejectedAttempt(t *testing.T) {
	lockAppSeams(t)

	input := strings.Join([]string{
		"", "",
		"short", "short",
		"correct horse battery staple", "",
		"different horse battery staple",
		"correct horse battery staple", "correct horse battery staple",
	}, "\n") + "\n"
	var out bytes.Buffer
	password, exists, err := setupResolvePassword(newSetupPrompter(strings.NewReader(input), &out), setupOptions{}, t.TempDir())
	if err != nil || exists || password != "correct horse battery staple" {
		t.Fatalf("expected setup to keep prompting until valid match, got password=%q exists=%v err=%v output=%q", password, exists, err, out.String())
	}
	text := out.String()
	for _, phrase := range []string{
		"Master password is required. Try again.",
		"master password must be at least",
		"Master passwords did not match. Try again.",
	} {
		if !strings.Contains(text, phrase) {
			t.Fatalf("expected retry phrase %q in output %q", phrase, text)
		}
	}
	if strings.Count(text, "Master passwords did not match. Try again.") != 1 {
		t.Fatalf("expected exactly one mismatch retry message, got %q", text)
	}
}

func TestSetupExistingVaultPasswordContractNeverExitsOnEmptyInput(t *testing.T) {
	lockAppSeams(t)

	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "vault.json.enc"), []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("write fake vault: %v", err)
	}

	cfg := &quick.Config{
		MaxCount: 64,
		Rand:     rand.New(rand.NewSource(2)),
	}
	property := func(raw uint8) bool {
		emptyEntries := int(raw % 32)
		var input strings.Builder
		for range emptyEntries {
			input.WriteString("\n")
		}
		input.WriteString("existing password\n")

		var out bytes.Buffer
		password, exists, err := setupResolvePassword(newSetupPrompter(strings.NewReader(input.String()), &out), setupOptions{}, home)
		if err != nil || !exists || password != "existing password" {
			t.Logf("emptyEntries=%d password=%q exists=%v err=%v output=%q", emptyEntries, password, exists, err, out.String())
			return false
		}
		retries := strings.Count(out.String(), "Master password is required. Try again.")
		if retries != emptyEntries {
			t.Logf("emptyEntries=%d retries=%d output=%q", emptyEntries, retries, out.String())
			return false
		}
		return true
	}
	if err := quick.Check(property, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestSetupExistingVaultOpenContractOnlyStopsAfterCorrectPassword(t *testing.T) {
	lockAppSeams(t)

	t.Setenv("HASP_HOME", t.TempDir())
	vaultStore, err := store.New(&memorySetupKeyring{})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	var out bytes.Buffer
	prompt := newSetupPrompter(strings.NewReader("\nwrong password\n\ncorrect horse battery staple\n"), &out)

	handle, state, password, err := setupOpenHandleWithRetry(context.Background(), prompt, vaultStore, "also wrong", true, false, false)
	if err != nil {
		t.Fatalf("expected retry loop to reach correct password, got %v output=%q", err, out.String())
	}
	if handle == nil || state != "existing" || password != "correct horse battery staple" {
		t.Fatalf("unexpected open result handle=%v state=%q password=%q", handle != nil, state, password)
	}
	text := out.String()
	if strings.Count(text, "invalid master password") != 2 {
		t.Fatalf("expected two invalid-password retries, got %q", text)
	}
	if strings.Count(text, "Master password is required. Try again.") != 2 {
		t.Fatalf("expected empty-password retries during existing-vault open, got %q", text)
	}
}

func TestSetupPasswordEOFRepeatGateRecognizesInteractiveDevice(t *testing.T) {
	lockAppSeams(t)

	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("pty unavailable: %v", err)
	}
	defer master.Close()
	defer slave.Close()
	if !setupCanRepeatPasswordAfterEOF(&setupPrompter{file: slave}) {
		t.Fatal("pty slave should be treated as an interactive device")
	}

	tempFile, err := os.CreateTemp(t.TempDir(), "setup-password-contract")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer tempFile.Close()
	if setupCanRepeatPasswordAfterEOF(&setupPrompter{file: tempFile}) {
		t.Fatal("regular files must not be treated as interactive devices")
	}
}

func TestSetupStageBoundaryContractSeparatesEveryPhase(t *testing.T) {
	lockAppSeams(t)

	var out bytes.Buffer
	if err := setupWriteIntro(&out); err != nil {
		t.Fatalf("setup intro: %v", err)
	}
	if err := setupWriteAgentMenu(&out, []setupAgentSpec{{
		ID:    "codex-cli",
		Label: "Codex CLI",
		ConfigPath: func(string) string {
			return "/tmp/.codex/config.toml"
		},
	}}, []string{"codex-cli"}); err != nil {
		t.Fatalf("agent menu: %v", err)
	}
	if err := setupWriteSelectedAgents(&out, []setupAgentSpec{{
		ID:    "codex-cli",
		Label: "Codex CLI",
		ConfigPath: func(string) string {
			return "/tmp/.codex/config.toml"
		},
	}}); err != nil {
		t.Fatalf("selected agents: %v", err)
	}
	if err := setupWriteConfirmation(&out, setupPlanPreview{
		HaspHome:         "/tmp/.hasp",
		AutoProtectRepos: true,
		InstallHooks:     true,
		Agents: []setupAgentSpec{{
			ID:    "codex-cli",
			Label: "Codex CLI",
			ConfigPath: func(string) string {
				return "/tmp/.codex/config.toml"
			},
		}},
	}); err != nil {
		t.Fatalf("confirmation: %v", err)
	}

	text := out.String()
	separator := strings.Repeat("-", 56)
	headers := []string{
		"== HASP setup ==",
		"== Agent setup ==",
		"== Agent targets ==",
		"== Review before apply ==",
	}
	for _, header := range headers {
		idx := strings.Index(text, header)
		if idx < 0 {
			t.Fatalf("missing setup phase header %q in %q", header, text)
		}
		before := text[:idx]
		lastLineStart := strings.LastIndex(before, "\n")
		if lastLineStart >= 0 {
			before = strings.TrimSuffix(before[:lastLineStart], "\n")
		}
		if !strings.HasSuffix(before, separator) {
			t.Fatalf("header %q was not immediately preceded by setup separator in %q", header, text)
		}
	}
	if got := strings.Count(text, separator); got != len(headers) {
		t.Fatalf("expected one separator per setup phase, got %d in %q", got, text)
	}
}
