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
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type doctorJSONReport struct {
	DaemonRunning           bool   `json:"daemon_running"`
	VaultState              string `json:"vault_state"`
	BindingState            string `json:"binding_state"`
	HooksInstalled          bool   `json:"hooks_installed"`
	PathShadowed            bool   `json:"path_shadowed"`
	PathHasNewer            bool   `json:"path_has_newer"`
	AgentMCPWrappersOK      bool   `json:"agent_mcp_wrappers_ok"`
	AuditDegraded           bool   `json:"audit_degraded"`
	ProcessIdentityDegraded bool   `json:"process_identity_degraded"`
	VersionMajor            int    `json:"version_major"`
	VersionMinor            int    `json:"version_minor"`
	VersionPatch            int    `json:"version_patch"`
}

type doctorReport struct {
	doctorJSONReport
	DaemonVersion         string
	VersionMismatch       bool
	ProjectRoot           string
	RedactorMinLength     int
	RedactorANSIAware     bool
	FixesAttempted        []string
	FixesSucceeded        []string
	FixesFailed           []string
	daemonDetail          string
	vaultDetail           string
	bindingDetail         string
	auditDetail           string
	processIdentityDetail string
	versionMismatchDetail string
	pathDetail            string
	agentMCPWrapperDetail string
}

func doctorCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", ".", "")
	fix := fs.Bool("fix", false, "")
	target := fs.String("target", "", "")
	profile := fs.String("profile", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp doctor [--json] [--fix] [--project-root <path>] [--target <integration-id>] [--profile <profile-id>]")
	}
	if strings.TrimSpace(*target) != "" {
		return doctorIntegrationCommand(ctx, strings.TrimSpace(*target), strings.TrimSpace(*profile), *jsonOutput || globalFlagsFromContext(ctx).json, stdout, s)
	}
	expandedRoot, err := expandUserPath(strings.TrimSpace(*projectRoot))
	if err != nil {
		return fmt.Errorf("--project-root: %w", err)
	}
	*projectRoot = expandedRoot
	report := buildDoctorReport(ctx, *projectRoot, s)
	if *fix {
		applyDoctorFixes(ctx, &report, s)
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

func doctorIntegrationCommand(ctx context.Context, target string, profile string, jsonOutput bool, stdout io.Writer, s starter) error {
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()
	reply, err := client.DoctorIntegration(ctx, runtime.IntegrationDoctorRPCRequest{TargetID: target, ProfileID: profile})
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSONResponse(stdout, reply)
	}
	return renderIntegrationDoctorHuman(stdout, reply)
}

func renderIntegrationDoctorHuman(stdout io.Writer, reply runtime.IntegrationDoctorResponse) error {
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "HASP integration doctor\t%s\t%t\n", reply.TargetID, reply.OK)
	if reply.ProfileID != "" {
		fmt.Fprintf(tw, "profile\t%s\n", reply.ProfileID)
	}
	fmt.Fprintf(tw, "runtime_probe\t%t\n", reply.RuntimeProbe)
	fmt.Fprintf(tw, "duration_ms\t%d\n", reply.DurationMS)
	for _, check := range reply.Checks {
		fmt.Fprintf(tw, "%s\t%t\t%s\n", check.Name, check.OK, check.Message)
		if check.FixHint != "" {
			fmt.Fprintf(tw, "%s_fix\t%s\n", check.Name, check.FixHint)
		}
	}
	return tw.Flush()
}

// applyDoctorFixes attempts a small, documented set of repairs. Each repair
// is recorded under FixesAttempted; on success it also lands in
// FixesSucceeded; on failure in FixesFailed. The helpers are deliberately
// conservative — they only touch files the daemon owns and never silently
// rewrite secret material.
func applyDoctorFixes(ctx context.Context, report *doctorReport, s starter) {
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
	if s != nil && !report.DaemonRunning {
		report.FixesAttempted = append(report.FixesAttempted, "start_daemon")
		if err := s.EnsureDaemon(ctx); err != nil {
			report.FixesFailed = append(report.FixesFailed, "start_daemon: "+err.Error())
		} else {
			report.FixesSucceeded = append(report.FixesSucceeded, "start_daemon")
			if status, ok := doctorRuntimeStatusFn(ctx, s); ok {
				report.DaemonRunning = true
				report.AuditDegraded = status.AuditDegraded
				report.ProcessIdentityDegraded = status.ProcessIdentityDegraded
				report.daemonDetail = "daemon is running"
			}
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
		if info, err := e.Info(); err == nil && info.Mode()&os.ModeSocket != 0 {
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
	checkedRoot := strings.TrimSpace(projectRoot)
	if canonicalRoot, err := appCanonicalProjectRootFn(ctx, checkedRoot); err == nil {
		checkedRoot = canonicalRoot
	}
	report := doctorReport{
		doctorJSONReport: doctorJSONReport{
			DaemonRunning:      false,
			VaultState:         "missing",
			BindingState:       "unknown",
			HooksInstalled:     false,
			AgentMCPWrappersOK: true,
			AuditDegraded:      false,
			VersionMajor:       major,
			VersionMinor:       minor,
			VersionPatch:       patch,
		},
		ProjectRoot:           checkedRoot,
		RedactorMinLength:     redactor.MinRedactLen,
		RedactorANSIAware:     redactor.ANSIAwareAvailable(),
		daemonDetail:          "daemon is not reachable; run hasp daemon start or retry the command",
		vaultDetail:           "vault is not initialized or cannot be unlocked",
		bindingDetail:         "project binding was not checked",
		auditDetail:           "audit subsystem reports healthy or unknown state",
		processIdentityDetail: "process binding identity probe reports healthy or unknown state",
		pathDetail:            "hasp executable PATH resolution looks consistent",
		agentMCPWrapperDetail: "managed agent MCP wrappers look consistent",
	}
	if pathDiagnostics := detectHaspPathDiagnostics(runtime.VersionString()); pathDiagnostics.Warning != "" {
		report.PathShadowed = pathDiagnostics.Shadowed
		report.PathHasNewer = pathDiagnostics.HasNewer
		report.pathDetail = pathDiagnostics.Warning
	}
	if wrapperDetail := detectManagedAgentMCPWrapperProblems(); wrapperDetail != "" {
		report.AgentMCPWrappersOK = false
		report.agentMCPWrapperDetail = wrapperDetail
	}

	if status, ok := doctorRuntimeStatusFn(ctx, s); ok {
		report.DaemonRunning = true
		report.AuditDegraded = status.AuditDegraded
		report.ProcessIdentityDegraded = status.ProcessIdentityDegraded
		report.daemonDetail = "daemon is running"
		if status.AuditDegraded {
			report.auditDetail = "audit append is degraded; check disk space, permissions, and the audit path"
		}
		if status.ProcessIdentityDegraded {
			report.processIdentityDetail = "implicit process binding is fail-closed"
			if status.ProcessIdentityDegradedReason != "" {
				report.processIdentityDetail += ": " + status.ProcessIdentityDegradedReason
			}
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
			report.bindingDetail = "project binding resolves for " + cliDisplayPath(report.ProjectRoot)
			report.HooksInstalled = bootstrapHookPresent(binding.CanonicalRoot)
		} else if err != nil {
			report.BindingState = "error"
			report.bindingDetail = doctorBindingFailureDetail(report.ProjectRoot, err)
		} else {
			report.BindingState = "unbound"
			report.bindingDetail = "project binding is missing for " + cliDisplayPath(report.ProjectRoot) + "; run hasp project bind --project-root " + strconv.Quote(report.ProjectRoot)
		}
	} else {
		report.VaultState = "missing"
		report.vaultDetail = "vault check failed; run hasp init or set HASP_MASTER_PASSWORD"
	}
	return report
}

func doctorBindingFailureDetail(projectRoot string, err error) string {
	var missingBindingItem store.MissingBindingItemError
	if errors.As(err, &missingBindingItem) {
		return missingBindingItem.Error()
	}
	return "project binding check failed for " + cliDisplayPath(projectRoot) + ": " + err.Error()
}

func doctorRuntimeStatus(ctx context.Context, s starter) (runtime.StatusResponse, bool) {
	if s == nil {
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
	if strings.TrimSpace(report.ProjectRoot) != "" {
		fmt.Fprintf(tw, "project_root\t%s\n", cliDisplayPath(report.ProjectRoot))
	}
	fmt.Fprintf(tw, "daemon\t%s\t%s\n", ui.Colorize(fmt.Sprintf("%t", report.DaemonRunning), boolRole(report.DaemonRunning), opts), report.daemonDetail)
	fmt.Fprintf(tw, "vault\t%s\t%s\n", ui.Colorize(report.VaultState, vaultRole(report.VaultState), opts), report.vaultDetail)
	fmt.Fprintf(tw, "binding\t%s\t%s\n", ui.Colorize(report.BindingState, bindingRole(report.BindingState), opts), report.bindingDetail)
	fmt.Fprintf(tw, "hooks\t%s\n", ui.Colorize(fmt.Sprintf("%t", report.HooksInstalled), boolRole(report.HooksInstalled), opts))
	pathOK := !report.PathShadowed && !report.PathHasNewer
	fmt.Fprintf(tw, "path_resolution\t%s\t%s\n", ui.Colorize(fmt.Sprintf("%t", pathOK), boolRole(pathOK), opts), report.pathDetail)
	fmt.Fprintf(tw, "agent_mcp_wrappers\t%s\t%s\n", ui.Colorize(fmt.Sprintf("%t", report.AgentMCPWrappersOK), boolRole(report.AgentMCPWrappersOK), opts), report.agentMCPWrapperDetail)
	fmt.Fprintf(tw, "audit_degraded\t%s\t%s\n", ui.Colorize(fmt.Sprintf("%t", report.AuditDegraded), auditDegradedRole(report.AuditDegraded), opts), report.auditDetail)
	fmt.Fprintf(tw, "process_identity_degraded\t%s\t%s\n", ui.Colorize(fmt.Sprintf("%t", report.ProcessIdentityDegraded), auditDegradedRole(report.ProcessIdentityDegraded), opts), report.processIdentityDetail)
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
