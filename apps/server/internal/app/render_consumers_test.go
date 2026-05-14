package app

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func TestRenderConsumerTablesAndConfigPolicy(t *testing.T) {
	var buf bytes.Buffer
	if err := renderConfig(&buf, runtime.ConfigDocument{"z": []any{"a", 2}, "a": []string{"x", "y"}, "n": 3}); err != nil {
		t.Fatalf("render config: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "KEY") || !strings.Contains(out, "a    x,y") || !strings.Contains(out, "z    a,2") {
		t.Fatalf("config output = %q", out)
	}
	if got := formatConfigValue(true); got != "true" {
		t.Fatalf("bool config value = %q", got)
	}

	buf.Reset()
	if err := renderPolicy(&buf, runtime.PolicyDocument{Version: "0"}); err != nil {
		t.Fatalf("render empty policy: %v", err)
	}
	if !strings.Contains(buf.String(), "has no rules") {
		t.Fatalf("empty policy output = %q", buf.String())
	}
	buf.Reset()
	if err := renderPolicy(&buf, runtime.PolicyDocument{Version: "1", Rules: []runtime.PolicyRule{{
		ID: "allow-ci", Match: runtime.PolicyMatch{Consumer: "ci", Secret: "prod/db", Scope: "read"}, Decision: "allow", TTLS: 60, MaxConcurrent: 2,
	}}}); err != nil {
		t.Fatalf("render policy: %v", err)
	}
	if !strings.Contains(buf.String(), "allow-ci") || !strings.Contains(buf.String(), "MAX") {
		t.Fatalf("policy output = %q", buf.String())
	}

	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	buf.Reset()
	if err := renderApprovalList(&buf, nil); err != nil {
		t.Fatalf("render empty approvals: %v", err)
	}
	if !strings.Contains(buf.String(), "No approvals.") {
		t.Fatalf("empty approvals output = %q", buf.String())
	}
	buf.Reset()
	if err := renderApprovalList(&buf, []runtime.Approval{{
		ID: "approval-1", Status: "pending", RequesterConsumerID: "agent", SecretID: "prod/db", RequestedScope: "read", RequestedAt: now, ExpiresAt: now.Add(time.Hour),
	}}); err != nil {
		t.Fatalf("render approvals: %v", err)
	}
	if !strings.Contains(buf.String(), "approval-1") || !strings.Contains(buf.String(), "CONSUMER") {
		t.Fatalf("approvals output = %q", buf.String())
	}

	buf.Reset()
	if err := renderLeaseList(&buf, nil); err != nil {
		t.Fatalf("render empty leases: %v", err)
	}
	if !strings.Contains(buf.String(), "No leases.") {
		t.Fatalf("empty leases output = %q", buf.String())
	}
	buf.Reset()
	if err := renderLeaseList(&buf, []runtime.Lease{{
		ID: "lease-1", Status: "active", SecretID: "prod/db", ConsumerID: "agent", Scope: "read", LastUsedAt: now, ExpiresAt: now.Add(time.Hour),
	}}); err != nil {
		t.Fatalf("render leases: %v", err)
	}
	if !strings.Contains(buf.String(), "lease-1") || !strings.Contains(buf.String(), "LAST_USED") {
		t.Fatalf("leases output = %q", buf.String())
	}

	buf.Reset()
	if err := renderIntegrationDoctorHuman(&buf, runtime.IntegrationDoctorResponse{
		TargetID:     "mcp",
		ProfileID:    "codex",
		OK:           false,
		RuntimeProbe: true,
		DurationMS:   12,
		Checks: []runtime.IntegrationDoctorCheck{{
			Name: "command", OK: false, Message: "missing", FixHint: "install",
		}},
	}); err != nil {
		t.Fatalf("render integration doctor: %v", err)
	}
	if !strings.Contains(buf.String(), "command_fix") || !strings.Contains(buf.String(), "duration_ms") {
		t.Fatalf("doctor output = %q", buf.String())
	}

	if !strings.Contains(telemetryConsentSummary(), "disabled by default") {
		t.Fatal("telemetry consent summary missing opt-in language")
	}
	for _, input := range []string{"y\n", "yes\n"} {
		if !confirmTelemetry(strings.NewReader(input), &buf) {
			t.Fatalf("confirmTelemetry(%q) = false", input)
		}
	}
	if confirmTelemetry(strings.NewReader("no\n"), nil) {
		t.Fatal("confirmTelemetry should default to false")
	}
}
