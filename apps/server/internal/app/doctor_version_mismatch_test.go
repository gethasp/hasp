package app

// hasp-8m5h: doctor must surface a CLI/daemon version mismatch as a warning
// (not a failure) and tell the operator to restart the daemon.

import (
	"context"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func TestBuildDoctorReportFlagsVersionMismatch(t *testing.T) {
	origStatus := doctorRuntimeStatusFn
	origPing := doctorDaemonPingFn
	t.Cleanup(func() {
		doctorRuntimeStatusFn = origStatus
		doctorDaemonPingFn = origPing
	})
	doctorRuntimeStatusFn = func(context.Context, starter) (runtime.StatusResponse, bool) {
		return runtime.StatusResponse{}, true
	}
	doctorDaemonPingFn = func(context.Context, starter) (string, bool) {
		// Pin a deliberately-different version so the comparison can't pass by
		// accident on a build that happens to match runtime.VersionString().
		return "0.0.1-stale", true
	}

	report := buildDoctorReport(context.Background(), ".", nil)
	if !report.VersionMismatch {
		t.Fatalf("expected VersionMismatch=true when daemon ping reports a different version: %+v", report)
	}
	if report.DaemonVersion != "0.0.1-stale" {
		t.Fatalf("DaemonVersion = %q, want 0.0.1-stale", report.DaemonVersion)
	}
	if !strings.Contains(report.versionMismatchDetail, "hasp daemon stop && hasp daemon start") {
		t.Fatalf("mismatch detail must suggest restart: %q", report.versionMismatchDetail)
	}
}

func TestBuildDoctorReportNoMismatchOnIdenticalVersions(t *testing.T) {
	origStatus := doctorRuntimeStatusFn
	origPing := doctorDaemonPingFn
	t.Cleanup(func() {
		doctorRuntimeStatusFn = origStatus
		doctorDaemonPingFn = origPing
	})
	doctorRuntimeStatusFn = func(context.Context, starter) (runtime.StatusResponse, bool) {
		return runtime.StatusResponse{}, true
	}
	doctorDaemonPingFn = func(context.Context, starter) (string, bool) {
		return runtime.VersionString(), true
	}

	report := buildDoctorReport(context.Background(), ".", nil)
	if report.VersionMismatch {
		t.Fatalf("expected VersionMismatch=false when daemon and CLI report same version: %+v", report)
	}
}

func TestBuildDoctorReportNoMismatchWhenDaemonUnreachable(t *testing.T) {
	origStatus := doctorRuntimeStatusFn
	origPing := doctorDaemonPingFn
	t.Cleanup(func() {
		doctorRuntimeStatusFn = origStatus
		doctorDaemonPingFn = origPing
	})
	doctorRuntimeStatusFn = func(context.Context, starter) (runtime.StatusResponse, bool) {
		return runtime.StatusResponse{}, false
	}
	doctorDaemonPingFn = func(context.Context, starter) (string, bool) {
		t.Fatal("ping should not run when status was unreachable")
		return "", false
	}

	report := buildDoctorReport(context.Background(), ".", nil)
	if report.VersionMismatch {
		t.Fatalf("expected no mismatch flag when daemon never answered: %+v", report)
	}
	if report.DaemonVersion != "" {
		t.Fatalf("DaemonVersion should be empty when daemon unreachable, got %q", report.DaemonVersion)
	}
}
