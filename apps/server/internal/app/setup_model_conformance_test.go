package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/setupmodel"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

const (
	setupConformanceStrongA = "correct horse battery staple"
	setupConformanceStrongB = "different horse battery staple"
	setupConformanceWeakA   = "short"
)

func TestSetupResolvePasswordConformanceWhitespaceOnlyNeverCompletesNewVault(t *testing.T) {
	lockAppSeams(t)

	input := strings.Join([]string{
		" ",
		"\t",
		"correct horse battery staple",
		"correct horse battery staple",
	}, "\n") + "\n"

	var out bytes.Buffer
	password, exists, err := setupResolvePassword(newSetupPrompter(strings.NewReader(input), &out), setupOptions{}, t.TempDir())
	if err != nil {
		t.Fatalf("setupResolvePassword: %v", err)
	}
	if exists {
		t.Fatal("expected new-vault flow")
	}
	if password != setupConformanceStrongA {
		t.Fatal("returned password did not match the expected strong candidate")
	}
	if got := strings.Count(out.String(), "Master password is required. Try again."); got != 2 {
		t.Fatalf("empty retry count=%d output=%q", got, out.String())
	}
	if strings.Contains(out.String(), "cancel") {
		t.Fatalf("whitespace-only attempts must not be reclassified as cancellation: %q", out.String())
	}
}

func TestSetupResolvePasswordConformanceWhitespaceOnlyNeverCompletesExistingVault(t *testing.T) {
	lockAppSeams(t)

	home := t.TempDir()
	if err := setupWriteFileFn(home+"/vault.json.enc", []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("write fake vault: %v", err)
	}

	var out bytes.Buffer
	password, exists, err := setupResolvePassword(newSetupPrompter(strings.NewReader(" \n\t\nexisting password\n"), &out), setupOptions{}, home)
	if err != nil {
		t.Fatalf("setupResolvePassword: %v", err)
	}
	if !exists {
		t.Fatal("expected existing-vault flow")
	}
	if password != "existing password" {
		t.Fatal("returned password did not match the expected existing-vault candidate")
	}
	if got := strings.Count(out.String(), "Master password is required. Try again."); got != 2 {
		t.Fatalf("empty retry count=%d output=%q", got, out.String())
	}
}

func TestSetupResolvePasswordConformanceSkipPolicyStillRequiresNonEmptyMatch(t *testing.T) {
	lockAppSeams(t)

	var out bytes.Buffer
	input := strings.Join([]string{
		"   ",
		"short",
		"different",
		"short",
		"short",
	}, "\n") + "\n"

	password, exists, err := setupResolvePassword(newSetupPrompter(strings.NewReader(input), &out), setupOptions{
		SkipPasswordPolicy: true,
	}, t.TempDir())
	if err != nil {
		t.Fatalf("setupResolvePassword: %v", err)
	}
	if exists {
		t.Fatal("expected new-vault flow")
	}
	if password != setupConformanceWeakA {
		t.Fatal("returned password did not match the expected weak candidate")
	}
	text := out.String()
	if got := strings.Count(text, "Master password is required. Try again."); got != 1 {
		t.Fatalf("empty retry count=%d output=%q", got, text)
	}
	if got := strings.Count(text, "Master passwords did not match. Try again."); got != 1 {
		t.Fatalf("mismatch retry count=%d output=%q", got, text)
	}
}

func TestSetupOpenHandleWithRetryConformanceWrongPasswordFailsNonInteractive(t *testing.T) {
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
	handle, state, password, err := setupOpenHandleWithRetry(
		context.Background(),
		newSetupPrompter(strings.NewReader("correct horse battery staple\n"), &out),
		vaultStore,
		"wrong password",
		true,
		true,
		false,
	)
	if !errors.Is(err, store.ErrInvalidPassword) {
		t.Fatalf("expected invalid-password failure, got handle=%v state=%q password_class=%s err=%v", handle, state, setupPasswordClass(password), err)
	}
	if handle != nil || state != "" {
		t.Fatalf("unexpected retry result handle=%v state=%q", handle, state)
	}
	if strings.Contains(out.String(), "invalid master password") {
		t.Fatalf("non-interactive wrong password must fail without retry output: %q", out.String())
	}
}

func TestSetupResolvePasswordConformancePreservesNonEmptyPasswordBytesFromEnv(t *testing.T) {
	lockAppSeams(t)

	const raw = "  keep surrounding spaces  "
	t.Setenv("SETUP_MASTER_PASSWORD", raw)

	password, exists, err := setupResolvePassword(newSetupPrompter(strings.NewReader(""), &bytes.Buffer{}), setupOptions{
		PasswordEnv: "SETUP_MASTER_PASSWORD",
	}, t.TempDir())
	if err != nil {
		t.Fatalf("setupResolvePassword: %v", err)
	}
	if exists {
		t.Fatal("expected new-vault flow")
	}
	if password != raw {
		t.Fatal("env password bytes changed")
	}
}

func TestSetupResolvePasswordConformancePreservesNonEmptyPasswordBytesFromStdin(t *testing.T) {
	lockAppSeams(t)

	const raw = "  keep surrounding spaces  "
	password, exists, err := setupResolvePassword(newSetupPrompter(strings.NewReader(raw), &bytes.Buffer{}), setupOptions{
		PasswordStdin: true,
	}, t.TempDir())
	if err != nil {
		t.Fatalf("setupResolvePassword: %v", err)
	}
	if exists {
		t.Fatal("expected new-vault flow")
	}
	if password != raw {
		t.Fatal("stdin password bytes changed")
	}
}

func TestSetupResolvePasswordConformanceGeneratedNewVaultTraces(t *testing.T) {
	lockAppSeams(t)

	for _, trace := range setupmodel.CanonicalTraces() {
		if trace.Mode.VaultExists || trace.Mode.Source != setupmodel.SourcePromptReader {
			continue
		}
		if !traceCoversResolvePassword(trace) {
			continue
		}
		t.Run(trace.Name, func(t *testing.T) {
			var out bytes.Buffer
			input := setupInputForNewVaultTrace(t, trace)
			password, exists, err := setupResolvePassword(newSetupPrompter(strings.NewReader(input), &out), setupOptions{
				SkipPasswordPolicy: trace.Mode.SkipPasswordPolicy,
			}, t.TempDir())
			if trace.Final == setupmodel.StateComplete {
				if err != nil {
					t.Fatalf("setupResolvePassword failed for abstract trace %q: %v", trace.Name, err)
				}
				if exists {
					t.Fatal("generated new-vault trace reported an existing vault")
				}
				if setupPasswordClass(password) != string(trace.Accepted) {
					t.Fatalf("accepted class mismatch: got %s want %s", setupPasswordClass(password), trace.Accepted)
				}
				assertOutputCount(t, out.String(), "Master password is required. Try again.", countOutput(trace, setupmodel.OutputRetryEmpty))
				assertOutputCount(t, out.String(), "Master passwords did not match. Try again.", countOutput(trace, setupmodel.OutputRetryMismatch))
				assertOutputCount(t, out.String(), "master password must be at least", countOutput(trace, setupmodel.OutputRetryWeak))
				return
			}
			if err == nil {
				t.Fatalf("abstract trace %q completed unexpectedly", trace.Name)
			}
		})
	}
}

func TestSetupOpenHandleWithRetryConformanceGeneratedExistingVaultTraces(t *testing.T) {
	lockAppSeams(t)

	for _, trace := range setupmodel.CanonicalTraces() {
		if !trace.Mode.VaultExists || trace.Mode.Source != setupmodel.SourcePromptReader {
			continue
		}
		if !traceCoversOpenRetry(trace) {
			continue
		}
		t.Run(trace.Name, func(t *testing.T) {
			vaultStore := newSetupConformanceStore(t)
			initialPassword, retryInput := setupExistingOpenInputs(t, trace)
			var out bytes.Buffer

			handle, state, password, err := setupOpenHandleWithRetry(
				context.Background(),
				newSetupPrompter(strings.NewReader(retryInput), &out),
				vaultStore,
				initialPassword,
				true,
				false,
				false,
			)
			if trace.Final == setupmodel.StateComplete {
				if err != nil {
					t.Fatalf("setupOpenHandleWithRetry failed for abstract trace %q: %v", trace.Name, err)
				}
				if handle == nil || state != "existing" {
					t.Fatalf("unexpected open result handle=%v state=%q", handle != nil, state)
				}
				if password != setupConformanceStrongA {
					t.Fatal("accepted existing-vault password did not match expected class")
				}
				assertOutputCount(t, out.String(), "invalid master password", countOutput(trace, setupmodel.OutputInvalidVault))
				assertOutputCount(t, out.String(), "Master password is required. Try again.", countOutput(trace, setupmodel.OutputRetryEmpty))
				return
			}
			if err == nil {
				t.Fatalf("abstract trace %q completed unexpectedly", trace.Name)
			}
		})
	}
}

func TestSetupResolvePasswordConformanceGeneratedNonInteractiveEmptyTraces(t *testing.T) {
	lockAppSeams(t)

	for _, trace := range setupmodel.CanonicalTraces() {
		t.Run(trace.Name, func(t *testing.T) {
			switch trace.Mode.Source {
			case setupmodel.SourcePasswordEnv:
				t.Setenv("SETUP_EMPTY_MASTER_PASSWORD", "   ")
				_, _, err := setupResolvePassword(newSetupPrompter(strings.NewReader(""), &bytes.Buffer{}), setupOptions{
					PasswordEnv: "SETUP_EMPTY_MASTER_PASSWORD",
				}, t.TempDir())
				if err == nil {
					t.Fatal("empty env source completed")
				}
			case setupmodel.SourcePasswordStdin:
				_, _, err := setupResolvePassword(newSetupPrompter(strings.NewReader("  \n\t"), &bytes.Buffer{}), setupOptions{
					PasswordStdin: true,
				}, t.TempDir())
				if err == nil {
					t.Fatal("empty stdin source completed")
				}
			}
		})
	}
}

func TestSetupResolvePasswordConformanceGeneratedExistingVaultTraces(t *testing.T) {
	lockAppSeams(t)

	for _, trace := range setupmodel.CanonicalTraces() {
		if !trace.Mode.VaultExists || trace.Mode.Source != setupmodel.SourcePromptReader {
			continue
		}
		if !traceCoversExistingResolve(trace) {
			continue
		}
		t.Run(trace.Name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.WriteFile(filepath.Join(home, "vault.json.enc"), []byte("placeholder"), 0o600); err != nil {
				t.Fatalf("write vault marker: %v", err)
			}
			var out bytes.Buffer
			input := setupInputForExistingResolveTrace(t, trace)
			password, exists, err := setupResolvePassword(newSetupPrompter(strings.NewReader(input), &out), setupOptions{}, home)
			if trace.Final == setupmodel.StateComplete {
				if err != nil {
					t.Fatalf("setupResolvePassword failed for abstract trace %q: %v", trace.Name, err)
				}
				if !exists {
					t.Fatal("generated existing-vault trace reported a new vault")
				}
				if password != setupConformanceStrongA {
					t.Fatal("accepted existing-vault password did not match expected class")
				}
				assertOutputCount(t, out.String(), "Master password is required. Try again.", countOutput(trace, setupmodel.OutputRetryEmpty))
				return
			}
			if err == nil {
				t.Fatalf("abstract trace %q completed unexpectedly", trace.Name)
			}
		})
	}
}

func TestSetupResolvePasswordConformancePromptReaderEmptyEOFFailsFast(t *testing.T) {
	lockAppSeams(t)

	_, _, err := setupResolvePassword(newSetupPrompter(strings.NewReader(""), &bytes.Buffer{}), setupOptions{}, t.TempDir())
	if err == nil {
		t.Fatal("prompt reader empty EOF completed")
	}
}

func traceCoversResolvePassword(trace setupmodel.Trace) bool {
	if trace.Mode.VaultExists {
		return false
	}
	for _, event := range trace.Events {
		switch event {
		case setupmodel.EventStrongCandidateA, setupmodel.EventStrongCandidateB,
			setupmodel.EventWeakCandidateA, setupmodel.EventConfirmMatchesPending,
			setupmodel.EventConfirmDiffers, setupmodel.EventEmptyLine,
			setupmodel.EventWhitespaceLine:
		default:
			return false
		}
	}
	return true
}

func traceCoversOpenRetry(trace setupmodel.Trace) bool {
	seenWrong := false
	for _, event := range trace.Events {
		switch event {
		case setupmodel.EventExistingWrongPassword:
			seenWrong = true
		case setupmodel.EventExistingRightPassword:
		default:
			return false
		}
	}
	return seenWrong
}

func traceCoversExistingResolve(trace setupmodel.Trace) bool {
	for _, event := range trace.Events {
		switch event {
		case setupmodel.EventExistingRightPassword, setupmodel.EventEmptyLine, setupmodel.EventWhitespaceLine:
		default:
			return false
		}
	}
	return true
}

func setupInputForNewVaultTrace(t *testing.T, trace setupmodel.Trace) string {
	t.Helper()
	var input strings.Builder
	var pending string
	for _, event := range trace.Events {
		switch event {
		case setupmodel.EventEmptyLine:
			input.WriteByte('\n')
		case setupmodel.EventWhitespaceLine:
			input.WriteString(" \t \n")
		case setupmodel.EventWeakCandidateA:
			pending = setupConformanceWeakA
			input.WriteString(setupConformanceWeakA + "\n")
		case setupmodel.EventStrongCandidateA:
			pending = setupConformanceStrongA
			input.WriteString(setupConformanceStrongA + "\n")
		case setupmodel.EventStrongCandidateB:
			pending = setupConformanceStrongB
			input.WriteString(setupConformanceStrongB + "\n")
		case setupmodel.EventConfirmMatchesPending:
			if pending == "" {
				t.Fatalf("trace %q confirms without a pending candidate", trace.Name)
			}
			input.WriteString(pending + "\n")
			pending = ""
		case setupmodel.EventConfirmDiffers:
			input.WriteString(setupConformanceStrongB + "\n")
			pending = ""
		default:
			t.Fatalf("trace %q cannot drive setupResolvePassword event %q", trace.Name, event)
		}
	}
	return input.String()
}

func setupExistingOpenInputs(t *testing.T, trace setupmodel.Trace) (string, string) {
	t.Helper()
	initialPassword := setupConformanceStrongA
	var retry strings.Builder
	usedInitial := false
	for _, event := range trace.Events {
		switch event {
		case setupmodel.EventExistingWrongPassword:
			if !usedInitial {
				initialPassword = setupConformanceStrongB
				usedInitial = true
			} else {
				retry.WriteString(setupConformanceStrongB + "\n")
			}
		case setupmodel.EventExistingRightPassword:
			if !usedInitial {
				initialPassword = setupConformanceStrongA
				usedInitial = true
			} else {
				retry.WriteString(setupConformanceStrongA + "\n")
			}
		case setupmodel.EventEmptyLine, setupmodel.EventWhitespaceLine:
			if !usedInitial {
				initialPassword = setupConformanceStrongB
				usedInitial = true
			}
			retry.WriteByte('\n')
		default:
			t.Fatalf("trace %q cannot drive setupOpenHandleWithRetry event %q", trace.Name, event)
		}
	}
	return initialPassword, retry.String()
}

func setupInputForExistingResolveTrace(t *testing.T, trace setupmodel.Trace) string {
	t.Helper()
	var input strings.Builder
	for _, event := range trace.Events {
		switch event {
		case setupmodel.EventEmptyLine:
			input.WriteByte('\n')
		case setupmodel.EventWhitespaceLine:
			input.WriteString(" \t \n")
		case setupmodel.EventExistingRightPassword:
			input.WriteString(setupConformanceStrongA + "\n")
		default:
			t.Fatalf("trace %q cannot drive existing setupResolvePassword event %q", trace.Name, event)
		}
	}
	return input.String()
}

func newSetupConformanceStore(t *testing.T) *store.Store {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HASP_HOME", home)
	vaultStore, err := store.New(&memorySetupKeyring{})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), setupConformanceStrongA); err != nil {
		t.Fatalf("init store: %v", err)
	}
	return vaultStore
}

func setupPasswordClass(password string) string {
	switch password {
	case setupConformanceWeakA:
		return string(setupmodel.CandidateWeakA)
	case setupConformanceStrongA:
		return string(setupmodel.CandidateStrongA)
	case setupConformanceStrongB:
		return string(setupmodel.CandidateStrongB)
	default:
		return "unknown"
	}
}

func assertOutputCount(t *testing.T, output, needle string, want int) {
	t.Helper()
	if got := strings.Count(output, needle); got != want {
		t.Fatalf("output count for %q = %d want %d", needle, got, want)
	}
}

func countOutput(trace setupmodel.Trace, output setupmodel.Output) int {
	count := 0
	for _, got := range trace.Outputs {
		if got == output {
			count++
		}
	}
	return count
}

func TestSetupResolvePasswordConformanceRegularFileEmptyEOFFailsFast(t *testing.T) {
	lockAppSeams(t)

	file, err := os.CreateTemp(t.TempDir(), "setup-password-conformance")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer file.Close()
	if _, err := file.WriteString("\n"); err != nil {
		t.Fatalf("seed temp file: %v", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatalf("rewind temp file: %v", err)
	}

	_, _, err = setupResolvePassword(newSetupPrompter(file, &bytes.Buffer{}), setupOptions{}, t.TempDir())
	if err == nil {
		t.Fatal("regular-file empty EOF completed")
	}
}

func TestSetupResolvePasswordConformanceVaultMarkerUsesRealFile(t *testing.T) {
	lockAppSeams(t)

	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "vault.json.enc"), []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("write vault marker: %v", err)
	}
	var out bytes.Buffer
	_, exists, err := setupResolvePassword(newSetupPrompter(strings.NewReader(" \n"), &out), setupOptions{}, home)
	if err == nil {
		t.Fatal("single empty existing-vault prompt should fail on prompt-reader EOF")
	}
	if !exists {
		t.Fatal("expected existing-vault flow")
	}
}
