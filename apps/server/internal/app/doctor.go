package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

type doctorJSONReport struct {
	DaemonRunning  bool   `json:"daemon_running"`
	VaultState     string `json:"vault_state"`
	BindingState   string `json:"binding_state"`
	HooksInstalled bool   `json:"hooks_installed"`
	AuditDegraded  bool   `json:"audit_degraded"`
	VersionMajor   int    `json:"version_major"`
	VersionMinor   int    `json:"version_minor"`
	VersionPatch   int    `json:"version_patch"`
}

type doctorReport struct {
	doctorJSONReport
	daemonDetail  string
	vaultDetail   string
	bindingDetail string
	auditDetail   string
}

func doctorCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", ".", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp doctor [--json] [--project-root <path>]")
	}
	report := buildDoctorReport(ctx, *projectRoot, s)
	if *jsonOutput {
		return json.NewEncoder(stdout).Encode(report.doctorJSONReport)
	}
	return renderDoctorHuman(stdout, report)
}

var doctorRuntimeStatusFn = doctorRuntimeStatus

func buildDoctorReport(ctx context.Context, projectRoot string, s starter) doctorReport {
	major, minor, patch := parseVersionParts(runtime.Version())
	report := doctorReport{
		doctorJSONReport: doctorJSONReport{
			DaemonRunning:  false,
			VaultState:     "missing",
			BindingState:   "unknown",
			HooksInstalled: false,
			AuditDegraded:  false,
			VersionMajor:   major,
			VersionMinor:   minor,
			VersionPatch:   patch,
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

func renderDoctorHuman(stdout io.Writer, report doctorReport) error {
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "HASP doctor")
	fmt.Fprintf(tw, "daemon\t%t\t%s\n", report.DaemonRunning, report.daemonDetail)
	fmt.Fprintf(tw, "vault\t%s\t%s\n", report.VaultState, report.vaultDetail)
	fmt.Fprintf(tw, "binding\t%s\t%s\n", report.BindingState, report.bindingDetail)
	fmt.Fprintf(tw, "hooks\t%t\n", report.HooksInstalled)
	fmt.Fprintf(tw, "audit_degraded\t%t\t%s\n", report.AuditDegraded, report.auditDetail)
	fmt.Fprintln(tw, "named_failure_paths\tmissing daemon, stale socket, missing wrapper, broken MCP config, missing vault, non-git repo, package drift, vault format mismatch, backup missing")
	return tw.Flush()
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
