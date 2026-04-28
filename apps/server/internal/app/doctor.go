package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/redactor"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

type doctorJSONReport struct {
	DaemonRunning      bool     `json:"daemon_running"`
	VaultState         string   `json:"vault_state"`
	BindingState       string   `json:"binding_state"`
	HooksInstalled     bool     `json:"hooks_installed"`
	AuditDegraded      bool     `json:"audit_degraded"`
	VersionMajor       int      `json:"version_major"`
	VersionMinor       int      `json:"version_minor"`
	VersionPatch       int      `json:"version_patch"`
	DaemonVersion      string   `json:"daemon_version"`
	VersionMismatch    bool     `json:"version_mismatch"`
	RedactorMinLength  int      `json:"redactor_min_length"`
	RedactorANSIAware  bool     `json:"redactor_ansi_aware"`
	FixesAttempted     []string `json:"fixes_attempted,omitempty"`
	FixesSucceeded     []string `json:"fixes_succeeded,omitempty"`
	FixesFailed        []string `json:"fixes_failed,omitempty"`
}

type doctorReport struct {
	doctorJSONReport
	daemonDetail          string
	vaultDetail           string
	bindingDetail         string
	auditDetail           string
	versionMismatchDetail string
}

func doctorCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", ".", "")
	fix := fs.Bool("fix", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp doctor [--json] [--fix] [--project-root <path>]")
	}
	expandedRoot, err := expandUserPath(strings.TrimSpace(*projectRoot))
	if err != nil {
		return fmt.Errorf("--project-root: %w", err)
	}
	*projectRoot = expandedRoot
	report := buildDoctorReport(ctx, *projectRoot, s)
	if *fix {
		applyDoctorFixes(&report)
	}
	if *jsonOutput || globalFlagsFromContext(ctx).json {
		return writeJSONResponse(stdout, report.doctorJSONReport)
	}
	gf := globalFlagsFromContext(ctx)
	opts := ui.ColorOptions{
		Interactive: ui.IsInteractiveWriter(stdout),
		Disable:     gf.noColor,
	}
	return renderDoctorHumanWithColor(stdout, report, opts)
}

// applyDoctorFixes attempts a small, documented set of repairs. Each repair
// is recorded under FixesAttempted; on success it also lands in
// FixesSucceeded; on failure in FixesFailed. The helpers are deliberately
// conservative — they only touch files the daemon owns and never silently
// rewrite secret material.
func applyDoctorFixes(report *doctorReport) {
	homeDir := os.Getenv("HASP_HOME")
	if homeDir == "" {
		report.FixesAttempted = append(report.FixesAttempted, "tighten_hasp_home_perms")
		report.FixesFailed = append(report.FixesFailed, "tighten_hasp_home_perms: HASP_HOME unset")
	} else {
		report.FixesAttempted = append(report.FixesAttempted, "tighten_hasp_home_perms")
		if err := os.Chmod(homeDir, 0o700); err != nil {
			report.FixesFailed = append(report.FixesFailed, "tighten_hasp_home_perms: "+err.Error())
		} else {
			report.FixesSucceeded = append(report.FixesSucceeded, "tighten_hasp_home_perms")
		}

		report.FixesAttempted = append(report.FixesAttempted, "remove_stale_sockets")
		removed, removeErr := removeStaleSocketsIn(homeDir)
		if removeErr != nil {
			report.FixesFailed = append(report.FixesFailed, "remove_stale_sockets: "+removeErr.Error())
		} else {
			report.FixesSucceeded = append(report.FixesSucceeded, fmt.Sprintf("remove_stale_sockets:%d", removed))
		}
	}
}

// removeStaleSocketsIn deletes any plain regular file ending in ".sock" under
// the given directory. The live daemon's socket is a unix domain socket
// (ModeSocket), not a regular file — so this never touches a working daemon
// even if HASP_HOME contains one. Returns the number removed.
func removeStaleSocketsIn(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".sock") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSocket != 0 {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
			removed++
		}
	}
	return removed, nil
}

var doctorRuntimeStatusFn = doctorRuntimeStatus

// doctorDaemonPingFn retrieves the daemon's reported version so doctor can
// flag CLI-vs-daemon drift (hasp-8m5h). Returns ("", false) when no daemon
// is reachable.
var doctorDaemonPingFn = doctorDaemonPing

func buildDoctorReport(ctx context.Context, projectRoot string, s starter) doctorReport {
	major, minor, patch := parseVersionParts(runtime.VersionString())
	report := doctorReport{
		doctorJSONReport: doctorJSONReport{
			DaemonRunning:     false,
			VaultState:        "missing",
			BindingState:      "unknown",
			HooksInstalled:    false,
			AuditDegraded:     false,
			VersionMajor:      major,
			VersionMinor:      minor,
			VersionPatch:      patch,
			RedactorMinLength: redactor.MinRedactLen,
			RedactorANSIAware: redactor.ANSIAwareAvailable(),
		},
		daemonDetail:  "daemon is not reachable; run hasp daemon start or retry the command",
		vaultDetail:   "vault is not initialized or cannot be unlocked",
		bindingDetail: "project binding was not checked",
		auditDetail:   "audit subsystem reports healthy or unknown state",
	}

	if status, ok := doctorRuntimeStatusFn(ctx, s); ok {
		report.DaemonRunning = true
		report.AuditDegraded = status.AuditDegraded
		report.daemonDetail = "daemon is running"
		if status.AuditDegraded {
			report.auditDetail = "audit append is degraded; check disk space, permissions, and the audit path"
		}
		if daemonVersion, ok := doctorDaemonPingFn(ctx, s); ok {
			report.DaemonVersion = daemonVersion
			cliVersion := strings.TrimSpace(strings.TrimPrefix(runtime.VersionString(), "v"))
			daemonTrimmed := strings.TrimSpace(strings.TrimPrefix(daemonVersion, "v"))
			if cliVersion != "" && daemonTrimmed != "" && cliVersion != daemonTrimmed {
				report.VersionMismatch = true
				report.versionMismatchDetail = fmt.Sprintf(
					"CLI %s vs daemon %s; restart the daemon: hasp daemon stop && hasp daemon start",
					cliVersion, daemonTrimmed,
				)
			}
		}
	}
	if handle, err := openVaultHandleFn(ctx); err == nil {
		report.VaultState = "unlocked"
		report.vaultDetail = "vault opens successfully"
		if binding, _, err := resolveBindingViewAppFn(handle, ctx, projectRoot); err == nil && binding.ID != "" {
			report.BindingState = "bound"
			report.bindingDetail = "project binding resolves"
			report.HooksInstalled = bootstrapHookPresent(binding.CanonicalRoot)
		} else {
			report.BindingState = "unbound"
			report.bindingDetail = "project binding is missing; run hasp project bind"
		}
	} else {
		report.VaultState = "missing"
		report.vaultDetail = "vault check failed; run hasp init or set HASP_MASTER_PASSWORD"
	}
	return report
}

func doctorRuntimeStatus(ctx context.Context, s starter) (runtime.StatusResponse, bool) {
	if s == nil {
		return runtime.StatusResponse{}, false
	}
	if err := s.EnsureDaemon(ctx); err != nil {
		return runtime.StatusResponse{}, false
	}
	client, err := s.Connect(ctx)
	if err != nil || client == nil {
		return runtime.StatusResponse{}, false
	}
	defer client.Close()
	status, err := client.Status(ctx)
	return status, err == nil
}

func doctorDaemonPing(ctx context.Context, s starter) (string, bool) {
	if s == nil {
		return "", false
	}
	client, err := s.Connect(ctx)
	if err != nil || client == nil {
		return "", false
	}
	defer client.Close()
	pong, err := client.Ping(ctx)
	if err != nil {
		return "", false
	}
	return pong.Version, true
}

// renderDoctorHumanWithColor is the rendering core. It applies the
// security-tool palette (green=healthy, yellow=warning, red=failure) to the
// state column when ui.ColorOptions allow it. The structural lines (column
// titles, named_failure_paths) are never colored so machine-readable
// post-processing keeps working.
func renderDoctorHumanWithColor(stdout io.Writer, report doctorReport, opts ui.ColorOptions) error {
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "HASP doctor")
	fmt.Fprintf(tw, "daemon\t%s\t%s\n", ui.Colorize(fmt.Sprintf("%t", report.DaemonRunning), boolRole(report.DaemonRunning), opts), report.daemonDetail)
	fmt.Fprintf(tw, "vault\t%s\t%s\n", ui.Colorize(report.VaultState, vaultRole(report.VaultState), opts), report.vaultDetail)
	fmt.Fprintf(tw, "binding\t%s\t%s\n", ui.Colorize(report.BindingState, bindingRole(report.BindingState), opts), report.bindingDetail)
	fmt.Fprintf(tw, "hooks\t%s\n", ui.Colorize(fmt.Sprintf("%t", report.HooksInstalled), boolRole(report.HooksInstalled), opts))
	fmt.Fprintf(tw, "audit_degraded\t%s\t%s\n", ui.Colorize(fmt.Sprintf("%t", report.AuditDegraded), auditDegradedRole(report.AuditDegraded), opts), report.auditDetail)
	if report.VersionMismatch {
		fmt.Fprintf(tw, "version_mismatch\t%s\t%s\n",
			ui.Colorize("true", ui.ColorWarn, opts), report.versionMismatchDetail)
	}
	fmt.Fprintf(tw, "redactor_min_length\t%d\n", report.RedactorMinLength)
	fmt.Fprintf(tw, "redactor_ansi_aware\t%s\n", ui.Colorize(fmt.Sprintf("%t", report.RedactorANSIAware), boolRole(report.RedactorANSIAware), opts))
	if len(report.FixesAttempted) > 0 {
		fmt.Fprintf(tw, "fixes_attempted\t%s\n", strings.Join(report.FixesAttempted, ", "))
	}
	if len(report.FixesSucceeded) > 0 {
		fmt.Fprintf(tw, "fixes_succeeded\t%s\n", ui.Colorize(strings.Join(report.FixesSucceeded, ", "), ui.ColorOK, opts))
	}
	if len(report.FixesFailed) > 0 {
		fmt.Fprintf(tw, "fixes_failed\t%s\n", ui.Colorize(strings.Join(report.FixesFailed, ", "), ui.ColorDeny, opts))
	}
	fmt.Fprintln(tw, "named_failure_paths\tmissing daemon, stale socket, missing wrapper, broken MCP config, missing vault, non-git repo, package drift, vault format mismatch, backup missing")
	return tw.Flush()
}

// boolRole returns ui.ColorOK for true, ui.ColorDeny for false. Used for the
// daemon and hooks rows where running/installed is healthy.
func boolRole(value bool) string {
	if value {
		return ui.ColorOK
	}
	return ui.ColorDeny
}

func vaultRole(state string) string {
	if state == "unlocked" {
		return ui.ColorOK
	}
	return ui.ColorDeny
}

func bindingRole(state string) string {
	switch state {
	case "bound":
		return ui.ColorOK
	case "unbound":
		return ui.ColorWarn
	default:
		return ui.ColorDeny
	}
}

// auditDegradedRole inverts the boolean: true (degraded) is a warning,
// false (healthy) is ok.
func auditDegradedRole(degraded bool) string {
	if degraded {
		return ui.ColorWarn
	}
	return ui.ColorOK
}

func parseVersionParts(version string) (int, int, int) {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.Split(version, ".")
	values := [3]int{}
	for i := 0; i < len(parts) && i < len(values); i++ {
		n, _ := strconv.Atoi(strings.TrimFunc(parts[i], func(r rune) bool { return r < '0' || r > '9' }))
		values[i] = n
	}
	return values[0], values[1], values[2]
}
