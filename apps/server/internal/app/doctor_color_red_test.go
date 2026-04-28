package app

// RED tests for hasp-e023 — wire color into hasp doctor. Contract pinned:
//
//   - When ui.ColorOptions.Interactive is true and Disable is false, the
//     doctor rows for daemon=true, vault=unlocked, audit_degraded=false
//     are wrapped with the ANSI green sequence; degraded states get
//     yellow/red.
//   - When ui.ColorOptions.Interactive is false (the default for bytes.Buffer
//     in tests), the output is plain text — no ANSI sequences appear.
//   - The structural lines (column titles, named_failure_paths) remain
//     unchanged regardless of color mode so machine-readable post-processing
//     keeps working.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/ui"
)

func TestRenderDoctorPlainHasNoAnsiSequences(t *testing.T) {
	report := doctorReport{
		doctorJSONReport: doctorJSONReport{
			DaemonRunning: true,
			VaultState:    "unlocked",
			BindingState:  "bound",
			AuditDegraded: false,
		},
		daemonDetail:  "daemon is running",
		vaultDetail:   "vault opens successfully",
		bindingDetail: "project binding resolves",
		auditDetail:   "audit subsystem reports healthy or unknown state",
	}
	var buf bytes.Buffer
	if err := renderDoctorHumanWithColor(&buf, report, ui.ColorOptions{Interactive: false}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Fatalf("expected no ANSI sequences in plain mode, got %q", buf.String())
	}
}

func TestRenderDoctorColorWrapsHealthyStatesGreen(t *testing.T) {
	report := doctorReport{
		doctorJSONReport: doctorJSONReport{
			DaemonRunning: true,
			VaultState:    "unlocked",
			BindingState:  "bound",
			AuditDegraded: false,
		},
		daemonDetail:  "daemon is running",
		vaultDetail:   "vault opens successfully",
		bindingDetail: "project binding resolves",
		auditDetail:   "audit subsystem reports healthy or unknown state",
	}
	var buf bytes.Buffer
	if err := renderDoctorHumanWithColor(&buf, report, ui.ColorOptions{Interactive: true}); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	// Green ANSI sequence (\x1b[32m) is in the palette for ui.ColorOK.
	if !strings.Contains(out, "\x1b[32m") {
		t.Fatalf("expected green ANSI sequence for healthy daemon, got %q", out)
	}
}

func TestRenderDoctorColorMarksDegradedStates(t *testing.T) {
	report := doctorReport{
		doctorJSONReport: doctorJSONReport{
			DaemonRunning: false,
			VaultState:    "missing",
			BindingState:  "unbound",
			AuditDegraded: true,
		},
		daemonDetail:  "daemon is not reachable; run hasp daemon start",
		vaultDetail:   "vault is not initialized or cannot be unlocked",
		bindingDetail: "project binding is missing",
		auditDetail:   "audit append is degraded",
	}
	var buf bytes.Buffer
	if err := renderDoctorHumanWithColor(&buf, report, ui.ColorOptions{Interactive: true}); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	// Red for daemon-not-running and vault-missing.
	if !strings.Contains(out, "\x1b[31m") {
		t.Fatalf("expected red ANSI sequence for failed states, got %q", out)
	}
	// Yellow for audit_degraded warning state.
	if !strings.Contains(out, "\x1b[33m") {
		t.Fatalf("expected yellow ANSI sequence for audit_degraded warning, got %q", out)
	}
}

func TestDoctorCommandReadsNoColorFromGlobalFlagsContext(t *testing.T) {
	// Even if some future change makes the writer interactive, --no-color
	// in the global flag context must still suppress ANSI sequences.
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := initCommandWithArgs(t.Context(), nil, &bytes.Buffer{}); err != nil {
		// init failures are unrelated to the test; we just need a vault dir.
		_ = err
	}
	starter := newDaemonTestStarter(t)
	var buf bytes.Buffer
	ctx := contextWithGlobalFlags(t.Context(), globalFlags{noColor: true})
	if err := doctorCommand(ctx, []string{}, &buf, starter); err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Fatalf("expected --no-color from context to suppress ANSI, got %q", buf.String())
	}
}

func TestRenderDoctorColorRespectsDisableFlag(t *testing.T) {
	report := doctorReport{
		doctorJSONReport: doctorJSONReport{DaemonRunning: true, VaultState: "unlocked", BindingState: "bound"},
		daemonDetail:    "daemon running",
		vaultDetail:     "vault unlocked",
		bindingDetail:   "binding ok",
		auditDetail:     "audit ok",
	}
	var buf bytes.Buffer
	if err := renderDoctorHumanWithColor(&buf, report, ui.ColorOptions{Interactive: true, Disable: true}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Fatalf("expected --no-color (disable) to suppress ANSI, got %q", buf.String())
	}
}
